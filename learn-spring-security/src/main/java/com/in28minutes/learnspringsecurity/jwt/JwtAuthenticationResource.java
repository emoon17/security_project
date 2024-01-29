package com.in28minutes.learnspringsecurity.jwt;

import java.time.Instant;
import java.util.stream.Collectors;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

//@RestController
public class JwtAuthenticationResource {

	private JwtEncoder jwtEncoder;
	
	public JwtAuthenticationResource(JwtEncoder jwtEncoder) {
		this.jwtEncoder = jwtEncoder;
	}
	
	@PostMapping("/authenticate")
	public JwtResponse autenticate(Authentication authentication) { // 주체 세부정보만 리턴하고 있다.
		
		//1. 어떤 token의 새로운 JwtResponse()를 생성하려고한다.
		//3. 2번에서 만든 Jwt token으로 JwtResponse를 생성한다.
		return new JwtResponse(createToken(authentication));
	}

	// 2. 메서드가 인증 객체를 받아서 JWt token를 생성하여 리턴한다.
	private String createToken(Authentication authentication) { 
		//JwtClaimsSet : Json Web Token이 전달한 클레임을 나타내는 json객체
		var claims = JwtClaimsSet.builder()
							.issuer("self")  // 발행한 발행자 설정
							.issuedAt(Instant.now()) // 시스템 시계에서 현재의 인스턴스를 획득한다.
							.expiresAt(Instant.now().plusSeconds(60 * 30)) // jwt토큰이 만료되는 시
							.subject(authentication.getName()) // 주제 설정 - 주체 이름
							.claim("scope", createScope(authentication)) // 3번 권한에 대한 설정을 scope에 설정한다.
							.build();
		//4. Jwt 토튼 만들기 위해 JwtEncoder 생성 --> 파라미터 필요 --> claims  
		return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
	}
	
	// 3. 특정한 유저가 가진 권한 - 나는 메소드 설정 --> 모든 권한에 대해 
	private String createScope(Authentication authentication) {
		// 메서드에서 모든 권한을 받을것이다.
		return authentication.getAuthorities().stream()
			.map(a -> a.getAuthority()) //받은 권한 리스트를 각각의 권한을 a.getAurhoriteies에 매핑할 것이다.
			.collect(Collectors.joining(" ")); // 모든 권한을 공백으로 구분해서 취합
	}
}


// 토큰과 함께 응답을 리턴
record JwtResponse(String token) {}