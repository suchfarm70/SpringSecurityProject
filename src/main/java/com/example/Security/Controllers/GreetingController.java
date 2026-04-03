package com.example.Security.Controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GreetingController {
    @GetMapping("/hello")
    public  String SayHello() {
        return "Hello ";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public  String UserEndpoint() {
        return "Hello ";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public  String AdminEndpoint() {
        return "Hello, Admin ";
    }
}
