package com.demo.rsademo.controller;

import com.demo.rsademo.vo.GetReq;
import com.demo.rsademo.vo.PostReq;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

/**
 * 模拟客户端
 */
@RestController
@RequestMapping("api")
public class ApiController {
    @GetMapping
    public ResponseEntity get(GetReq params, HttpSession httpSession) {
        return new ResponseEntity(params, HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity post(PostReq params, HttpSession httpSession) {
        return new ResponseEntity(params, HttpStatus.OK);
    }
}
