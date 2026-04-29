package com.lab.ghostbits.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.*;

@Service
public class GhostBitsService {

    private static final Set<String> DANGEROUS_EXTENSIONS = Set.of(".jsp", ".jspx", ".php", ".exe", ".sh", ".bat", ".cmd", ".war");
    private static final String[] DANGEROUS_PATTERNS = {
            "../", "..\\", ".jsp", ".php", ".exe", ".sh", ".bat",
            "<script", "union ", "select ", "drop ", "delete ", "insert ",
            "' or", "' and", "\" or", "\" and", "--",
            "cat /", "rm -", "/etc/passwd", "/etc/shadow",
            "runtime", "exec(", "getruntime", "processbuilder",
            "classloader", "bcel"
    };

    public Map<String, Object> analyze(String input) {
        List<Map<String, Object>> chars = new ArrayList<>();
        StringBuilder transformed = new StringBuilder();

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int codePoint = c;
            int lowByte = c & 0xFF;
            char lowChar = (char) lowByte;

            Map<String, Object> info = new LinkedHashMap<>();
            info.put("index", i);
            info.put("char", String.valueOf(c));
            info.put("unicode", "U+" + String.format("%04X", codePoint));
            info.put("fullHex", "0x" + String.format("%04X", codePoint));
            info.put("lowByte", "0x" + String.format("%02X", lowByte));
            info.put("lowByteDec", lowByte);
            info.put("resultChar", escapeControl(String.valueOf(lowChar)));
            info.put("isGhost", codePoint > 0xFF);
            info.put("highBitsLost", codePoint > 0xFF ? "0x" + String.format("%02X", (codePoint >> 8)) : "-");
            chars.add(info);

            transformed.append(lowChar);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("input", input);
        result.put("inputLength", input.length());
        result.put("transformed", escapeControl(transformed.toString()));
        result.put("ghostCount", chars.stream().filter(c -> (boolean) c.get("isGhost")).count());
        result.put("chars", chars);
        return result;
    }

    public Map<String, Object> wafCheck(String input) {
        boolean wafBlocked = isDangerous(input);
        String wafReason = getDangerousReason(input);
        List<String> wafMatches = getDangerousMatches(input);

        String processed = ghostBitsTransform(input);
        boolean backendDangerous = isDangerous(processed);
        String backendReason = getDangerousReason(processed);
        List<String> backendMatches = getDangerousMatches(processed);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("input", input);
        result.put("inputDisplay", escapeControl(input));

        Map<String, Object> waf = new LinkedHashMap<>();
        waf.put("sees", escapeControl(input));
        waf.put("blocked", wafBlocked);
        waf.put("reason", wafReason);
        waf.put("matches", wafMatches);
        result.put("waf", waf);

        Map<String, Object> backend = new LinkedHashMap<>();
        backend.put("sees", escapeControl(processed));
        backend.put("dangerous", backendDangerous);
        backend.put("reason", backendReason);
        backend.put("matches", backendMatches);
        result.put("backend", backend);

        result.put("bypassed", !wafBlocked && backendDangerous);
        return result;
    }

    public Map<String, Object> processUpload(String filename) {
        if (filename == null) filename = "unknown";

        String transformed = ghostBitsTransform(filename);

        boolean wafBlocked = isDangerousExtension(filename);
        String wafReason = isDangerousExtension(filename)
                ? "WAF 拦截: 危险扩展名 " + getDangerousExtension(filename)
                : "WAF 通过: 扩展名安全";

        boolean backendDangerous = isDangerousExtension(transformed);
        String backendReason = isDangerousExtension(transformed)
                ? "后端执行: 危险扩展名 " + getDangerousExtension(transformed)
                : "后端执行: 扩展名安全";

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("originalName", filename);
        result.put("savedName", escapeControl(transformed));
        result.put("wafBlocked", wafBlocked);
        result.put("wafReason", wafReason);
        result.put("backendDangerous", backendDangerous);
        result.put("backendReason", backendReason);
        result.put("bypassed", !wafBlocked && backendDangerous);
        return result;
    }

    public Map<String, Object> processPath(String path) {
        String transformed = ghostBitsTransform(path);

        boolean wafBlocked = isDangerousPath(path);
        boolean backendDangerous = isDangerousPath(transformed);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("input", path);
        result.put("transformed", escapeControl(transformed));
        result.put("wafBlocked", wafBlocked);
        result.put("wafReason", wafBlocked ? "WAF 拦截: 检测到路径穿越" : "WAF 通过: 路径安全");
        result.put("backendDangerous", backendDangerous);
        result.put("backendReason", backendDangerous ? "后端执行: 检测到路径穿越" : "后端执行: 路径安全");
        result.put("bypassed", !wafBlocked && backendDangerous);
        return result;
    }

    String ghostBitsTransform(String input) {
        byte[] bytes = new byte[input.length()];
        for (int i = 0; i < input.length(); i++) {
            bytes[i] = (byte) input.charAt(i);
        }
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }

    private boolean isDangerous(String input) {
        String lower = input.toLowerCase();
        for (String pattern : DANGEROUS_PATTERNS) {
            if (lower.contains(pattern)) return true;
        }
        return false;
    }

    private String getDangerousReason(String input) {
        List<String> matches = getDangerousMatches(input);
        return matches.isEmpty() ? "未检测到危险内容" : "检测到: " + String.join(", ", matches);
    }

    private List<String> getDangerousMatches(String input) {
        String lower = input.toLowerCase();
        List<String> matches = new ArrayList<>();
        for (String pattern : DANGEROUS_PATTERNS) {
            if (lower.contains(pattern)) {
                matches.add(pattern.trim());
            }
        }
        return matches;
    }

    private boolean isDangerousExtension(String filename) {
        String lower = filename.toLowerCase();
        return DANGEROUS_EXTENSIONS.stream().anyMatch(lower::endsWith);
    }

    private String getDangerousExtension(String filename) {
        String lower = filename.toLowerCase();
        return DANGEROUS_EXTENSIONS.stream().filter(lower::endsWith).findFirst().orElse("");
    }

    private boolean isDangerousPath(String path) {
        String lower = path.toLowerCase();
        return lower.contains("../") || lower.contains("..\\") ||
               lower.contains("/etc/") || lower.contains("\\windows\\");
    }

    private String escapeControl(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '\r') sb.append("\\r");
            else if (c == '\n') sb.append("\\n");
            else if (c == '\t') sb.append("\\t");
            else if (c == '\0') sb.append("\\0");
            else if (c < 0x20) sb.append(String.format("\\x%02x", (int) c));
            else sb.append(c);
        }
        return sb.toString();
    }
}
