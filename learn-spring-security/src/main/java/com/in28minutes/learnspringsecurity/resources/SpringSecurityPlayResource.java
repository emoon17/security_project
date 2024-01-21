package com.in28minutes.learnspringsecurity.resources;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
public class SpringSecurityPlayResource {

	//1. 폼기반 인증-기본 폼과 기본 로그아웃 페이지를 제공하고 로그아웃 기능도 제공한다.
	// 2. 인증을 하면 요청 헤더에 쿠키가 생성된다.
	//3. 쿠키가 요청과 함께 전송되어 Spring Security가 자동으로 인증한다.
	
	@GetMapping("/csrf-token")
	public CsrfToken retrieveCsffToken(HttpServletRequest request) {
		return (CsrfToken) request.getAttribute("_csrf");
	}
}
