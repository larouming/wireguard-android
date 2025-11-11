/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
 
/*
 * TXT解析逻辑：
 * 如果检测到endpoint_host为域名以及endpoint_port为1，对域名进行TXT解析获得空格分隔的地址:端口列表（去除引号）
 * 配置状态标记，connect=1
 * 遍历获得的列表，验证地址格式并拆分IP和端口（支持IPv4:port和[IPv6]:port）
 * 测试对端IP的可达性，将第一个有效的IP则封装为有效端点，停止遍历
 * 如果检测到endpoint_host不为域名或者endpoint_port不为1，跳过TXT解析流程，按原逻辑处理
 * 将改动控制在最小范围内，尽量使用原生库或者类
 * 列出所有改动并解释代码的作用 
 * 优化日志输出内容，确保 TXT 记录解析全过程和可达性测试结果都能通过中文日志清晰展示。
 */
package com.wireguard.config;
 
import com.wireguard.util.NonNullForAll;
 
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Name;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;
import org.xbill.DNS.Type;
 
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
 
import android.util.Log;
import androidx.annotation.Nullable;
 
 
/**
 * WireGuard 对等节点（Peer）的外部端点封装（host + port）
 * 功能：解析端点字符串、处理DNS解析（常规DNS/TXT记录）、线程安全的解析缓存
 */
@NonNullForAll
public final class InetEndpoint {
    // 日志标签：便于筛选该类相关日志
    private static final String TAG = "InetEndpoint";
    // 匹配"纯IPv6地址"（无方括号）的正则：用于toString()时添加方括号
    private static final Pattern BARE_IPV6 = Pattern.compile("^[^\\[\\]]*:[^\\[\\]]*");
    // 匹配URL中禁止出现在host中的字符（避免恶意端点字符串）
    private static final Pattern FORBIDDEN_CHARACTERS = Pattern.compile("[/?#]");
 
    private final String host;          // 端点主机（域名或IP）
    private final boolean isResolved;   // 标记：host是否已为IP（true=IP，false=域名）
    private final Object lock = new Object();  // 同步锁：保证多线程下解析操作安全
    private final int port;             // 端点端口
    private Instant lastResolution = Instant.EPOCH;  // 上次解析时间：用于1分钟缓存
    @Nullable private InetEndpoint resolved;  // 解析结果缓存：存IP+port的端点
 
 
    /**
     * 私有构造：仅通过parse()或解析方法创建实例，保证端点合法性
     */
    private InetEndpoint(final String host, final boolean isResolved, final int port) {
        this.host = host;
        this.isResolved = isResolved;
        this.port = port;
    }
 
 
    /**
     * 公开方法：将字符串端点（如"example.com:1"或"192.168.1.1:51820"）解析为InetEndpoint实例
     * @param endpoint 端点字符串（格式：host:port）
     * @return 合法的InetEndpoint实例
     * @throws ParseException 解析失败（如非法字符、无效端口、IP格式错误）
     */
    public static InetEndpoint parse(final String endpoint) throws ParseException {
        // 过滤非法字符，避免恶意输入
        if (FORBIDDEN_CHARACTERS.matcher(endpoint).find())
            throw new ParseException(InetEndpoint.class, endpoint, "端点包含禁止字符（/、?、#）");
 
        // 用URI解析器处理端点（避免手动分割host和port的复杂逻辑）
        final URI uri;
        try {
            // 包装为"wg://host:port"格式，让URI自动识别host和port
            uri = new URI("wg://" + endpoint);
        } catch (final URISyntaxException e) {
            throw new ParseException(InetEndpoint.class, endpoint, "端点格式非法（需host:port）", e);
        }
 
        // 验证端口合法性（1-65535）
        if (uri.getPort() < 0 || uri.getPort() > 65535)
            throw new ParseException(InetEndpoint.class, endpoint, "端口无效（需1-65535）");
 
        // 判断host是IP还是域名：尝试解析为IP，成功则标记isResolved=true
        try {
            InetAddresses.parse(uri.getHost()); // 调用WireGuard工具类验证IP格式
            Log.d(TAG, "解析端点为IP地址: " + uri.getHost() + ":" + uri.getPort());
            return new InetEndpoint(uri.getHost(), true, uri.getPort()); // 是IP：无需后续DNS解析
        } catch (final ParseException ignored) {
            Log.d(TAG, "解析端点为域名: " + uri.getHost() + ":" + uri.getPort());
            return new InetEndpoint(uri.getHost(), false, uri.getPort()); // 是域名：需要后续DNS解析
        }
    }
 
 
    /**
     * 核心方法：解析端点为"IP+port"格式（处理常规DNS或TXT记录）
     * 逻辑：1分钟内缓存有效，线程安全；根据port和host类型选择解析方式
     * @return 解析后的端点（IP+port），失败则返回空
     */
    public Optional<InetEndpoint> getResolved() {
        // 若已为IP（isResolved=true），直接返回自身
        if (isResolved) {
            Log.d(TAG, "已为IP地址，无需解析: " + host + ":" + port);
            return Optional.of(this);
        }
 
        // 同步锁：避免多线程同时触发解析
        synchronized (lock) {
            // 缓存逻辑：超过1分钟重新解析，避免过期IP
            long minutesSinceLast = Duration.between(lastResolution, Instant.now()).toMinutes();
            if (minutesSinceLast > 1) {
                Log.d(TAG, "解析缓存已过期（" + minutesSinceLast + "分钟），重新解析: " + host + ":" + port);
                try {
                    // 仅当「host是域名（isResolved=false）且port=1」时，触发TXT解析
                    if (port == 1) {
                        Log.d(TAG, "检测到端口为1，触发TXT记录解析流程");
                        resolved = resolveTxtRecord(); // TXT记录解析逻辑
                    } else {
                        Log.d(TAG, "端口不为1，使用常规DNS解析流程");
                        resolved = resolveNormalDns(); // 常规DNS解析（域名→IP）
                    }
                    lastResolution = Instant.now(); // 更新缓存时间
                } catch (final UnknownHostException | TextParseException e) {
                    resolved = null; // 解析失败：清空缓存
                    Log.e(TAG, "端点解析失败：" + host + ":" + port, e);
                }
            } else {
                Log.d(TAG, "使用缓存的解析结果（" + minutesSinceLast + "分钟前更新）");
            }
            return Optional.ofNullable(resolved); // 返回解析结果（空=失败）
        }
    }
 
 
    /**
     * TXT记录解析逻辑
     * 流程：查询TXT记录 → 处理记录内容 → 验证地址格式 → 测试可达性 → 返回第一个有效地址
     * @return 有效IP+port的端点，失败则返回null
     */
    @Nullable
    private InetEndpoint resolveTxtRecord() throws TextParseException, UnknownHostException {
        Log.d(TAG, "开始TXT记录解析流程：" + host + "（端口=1）");
 
        // 1. 发起TXT记录DNS查询（使用公共DNS：114.114.114.114，避免本地DNS污染）
        Log.d(TAG, "步骤1/4：向DNS服务器114.114.114.114查询TXT记录");
        final Lookup txtLookup = new Lookup(Name.fromString(host), Type.TXT);
        txtLookup.setCache(null); // 禁用缓存：确保获取最新TXT记录
        txtLookup.setResolver(new SimpleResolver("114.114.114.114")); // 公共DNS服务器
        final Record[] txtRecords = txtLookup.run();
 
        // 检查查询结果：无TXT记录则返回失败
        if (txtLookup.getResult() != Lookup.SUCCESSFUL || txtRecords == null || txtRecords.length == 0) {
            Log.w(TAG, "步骤1/4：未查询到TXT记录，解析失败（结果代码：" + txtLookup.getResult() + "）");
            return null;
        }
        Log.d(TAG, "步骤1/4：成功查询到" + txtRecords.length + "条TXT记录");
 
        // 2. 处理TXT记录内容（去引号、空格分隔地址列表）
        Log.d(TAG, "步骤2/4：开始处理TXT记录内容");
        final TXTRecord txtRecord = (TXTRecord) txtRecords[0];
        // 拼接TXT记录的多段内容（DNS协议允许TXT记录分块）→ 去引号 → 按空格分割
        String txtContent = String.join("", txtRecord.getStrings()).trim().replace("\"", "");
        Log.d(TAG, "步骤2/4：TXT记录原始内容（去引号后）：" + txtContent);
        
        String[] addressList = txtContent.split("\\s+"); // 空格分隔为地址数组
        // 过滤空地址：避免分割后出现空字符串
        List<String> validAddressList = new ArrayList<>();
        for (String addr : addressList) {
            if (!addr.isEmpty()) validAddressList.add(addr);
        }
        Log.d(TAG, "步骤2/4：解析到" + validAddressList.size() + "个地址：" + validAddressList);
 
        // 连接状态标记（1=未找到有效地址，0=找到有效地址）
        int connect = 1;
        InetEndpoint validEndpoint = null;
 
        // 3. 验证地址格式（支持IPv4:port和[IPv6]:port）
        Log.d(TAG, "步骤3/4：开始验证地址格式并测试可达性");
        // 正则说明：
        // - IPv4段：(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5}) → 如192.168.1.1:51820
        // - IPv6段：\[([0-9a-fA-F:]+)\]:(\d{1,5}) → 如[2001::1]:51820
        final Pattern addrPattern = Pattern.compile(
            "^(?:(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}):(\\d{1,5})|\\[([0-9a-fA-F:]+)\\]:(\\d{1,5}))$"
        );
 
        // 4. 遍历地址列表（测试可达性，保存第一个有效地址并停止遍历）
        for (int i = 0; i < validAddressList.size(); i++) {
            String addr = validAddressList.get(i);
            Log.d(TAG, "处理第" + (i+1) + "/" + validAddressList.size() + "个地址：" + addr);
            
            Matcher addrMatcher = addrPattern.matcher(addr);
            if (!addrMatcher.matches()) { // 地址格式不匹配，跳过
                Log.w(TAG, "地址格式非法，跳过：" + addr + "（需符合IPv4:port或[IPv6]:port格式）");
                continue;
            }
 
            // 提取IP和port（区分IPv4/IPv6）
            String ip;
            int port;
            if (addrMatcher.group(1) != null) { // IPv4地址（group1=IP，group2=port）
                ip = addrMatcher.group(1);
                port = Integer.parseInt(addrMatcher.group(2));
                Log.d(TAG, "解析到IPv4地址：" + ip + "，端口：" + port);
            } else { // IPv6地址（group3=IP，group4=port）
                ip = addrMatcher.group(3);
                port = Integer.parseInt(addrMatcher.group(4));
                Log.d(TAG, "解析到IPv6地址：" + ip + "，端口：" + port);
            }
 
            // 二次验证port合法性（1-65535）
            if (port < 1 || port > 65535) {
                Log.w(TAG, "端口非法（需1-65535），跳过：" + port + "，地址：" + addr);
                continue;
            }
 
            // 测试IP可达性（超时1秒：避免阻塞太久）
            Log.d(TAG, "开始可达性测试：" + ip + "（超时1秒）");
            try {
                InetAddress targetIp = InetAddress.getByName(ip);
                long startTime = System.currentTimeMillis();
                boolean isReachable = targetIp.isReachable(1000);
                long costTime = System.currentTimeMillis() - startTime;
                
                if (isReachable) { // 可达性测试通过
                    Log.d(TAG, "可达性测试成功（耗时" + costTime + "ms）：" + ip);
                    validEndpoint = new InetEndpoint(ip, true, port); // 封装为有效端点
                    connect = 0; // 标记：找到有效地址
                    Log.d(TAG, "找到第一个有效地址，停止遍历：" + ip + ":" + port);
                    break; // 找到第一个有效地址即停止遍历
                } else {
                    Log.d(TAG, "可达性测试失败（耗时" + costTime + "ms）：" + ip);
                }
            } catch (IOException e) {
                Log.w(TAG, "可达性测试发生异常：" + ip, e);
            }
        }
 
        // 根据connect状态返回结果（0=有效，1=无效）
        if (connect == 0) {
            Log.d(TAG, "TXT记录解析成功，返回有效地址：" + validEndpoint);
            return validEndpoint;
        } else {
            Log.w(TAG, "TXT记录解析完成，未找到任何有效地址");
            return null;
        }
    }
 
 
    /**
     * 常规DNS解析（域名→IP）
     * 逻辑：解析域名到所有IP → 优先选择IPv4（兼容性更好）→ 封装为IP+port端点
     * @return 解析后的IP+port端点，失败则返回null
     */
    @Nullable
    private InetEndpoint resolveNormalDns() throws UnknownHostException {
        Log.d(TAG, "开始常规DNS解析流程：" + host + ":" + port);
 
        // 解析域名到所有IP（可能包含IPv4和IPv6）
        Log.d(TAG, "查询域名对应的所有IP地址");
        final InetAddress[] ipCandidates = InetAddress.getAllByName(host);
        Log.d(TAG, "共查询到" + ipCandidates.length + "个IP地址");
        
        InetAddress targetIp = ipCandidates[0]; // 默认取第一个IP
 
        // 优先选择IPv4（避免部分网络不支持IPv6的问题）
        for (InetAddress ip : ipCandidates) {
            if (ip instanceof Inet4Address) {
                targetIp = ip;
                Log.d(TAG, "发现IPv4地址，优先选择：" + targetIp.getHostAddress());
                break;
            }
        }
 
        // 封装为IP+port的端点（isResolved=true）
        final String ipStr = targetIp.getHostAddress();
        Log.d(TAG, "常规DNS解析完成：" + host + " → " + ipStr + ":" + port);
        return new InetEndpoint(ipStr, true, port);
    }
 
 
    // ------------------------------ 以下为原有工具方法（无修改）------------------------------
    @Override
    public boolean equals(final Object obj) {
        if (!(obj instanceof InetEndpoint)) return false;
        final InetEndpoint other = (InetEndpoint) obj;
        return host.equals(other.host) && port == other.port;
    }
 
    public String getHost() { return host; }
 
    public int getPort() { return port; }
 
    @Override
    public int hashCode() { return host.hashCode() ^ port; }
 
    /**
     * 端点字符串格式化：IPv6地址自动添加方括号（如[2001::1]:51820）
     */
    @Override
    public String toString() {
        final boolean isIpv6 = isResolved && BARE_IPV6.matcher(host).matches();
        return (isIpv6 ? "[" + host + "]" : host) + ":" + port;
    }
}
