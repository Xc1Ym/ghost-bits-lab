package com.lab.ghostbits.controller;

import com.lab.ghostbits.service.GhostBitsService;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class LabController {

    private final GhostBitsService service;

    public LabController(GhostBitsService service) {
        this.service = service;
    }

    @PostMapping("/transform")
    public Map<String, Object> transform(@RequestBody Map<String, String> body) {
        String input = body.getOrDefault("input", "");
        return service.analyze(input);
    }

    @PostMapping("/waf-bypass")
    public Map<String, Object> wafBypass(@RequestBody Map<String, String> body) {
        String input = body.getOrDefault("input", "");
        return service.wafCheck(input);
    }

    @PostMapping("/upload")
    public Map<String, Object> upload(@RequestParam("file") MultipartFile file) {
        return service.processUpload(file.getOriginalFilename());
    }

    @GetMapping("/read-file")
    public Map<String, Object> readFile(@RequestParam String path) {
        return service.processPath(path);
    }
}
