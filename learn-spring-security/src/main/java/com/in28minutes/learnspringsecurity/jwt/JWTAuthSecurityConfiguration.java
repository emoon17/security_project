package com.in28minutes.learnspringsecurity.jwt;

import static org.springframework.security.config.Customizer.withDefaults;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

//CSRF 해제하기
@Configuration
public class JWTAuthSecurityConfiguration {

	// SecurityFilterChain으로 Spring Security에서 보안 필터를 연결하고 구성
	@Bean
	SecurityFilterChain SecurityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests( // 모든 요청에 대한 인증이 필요하다.
				auth -> {
					auth.anyRequest().authenticated();
				});
		http.sessionManagement( // 세션 관리 정책을 설정
				session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS) // STATELESS: 세션사용하지 않는다는뜻.
		);
		// http.formLogin(withDefaults());
		http.httpBasic(withDefaults());

		// csrf 해제
		http.csrf().disable();

		http.headers().frameOptions().sameOrigin(); // Clickjacking 공격을 방어하기 위한 것

		// oauth2 리소스 설정 - Consider defining a bean of type
		// 'org.springframework.security.oauth2.jwt.JwtDecoder' in your configuration.
		// 오류 발생 : securityFilterChain 메서드가 JwtDecoder 타입의 Bean을 요구했는데 그걸 찾을 수 없다.
		// OAuth2 리소스 서버 설정하는데 이 리소스 서버거 JWT 토큰을 받으면 그걸 디코딩해야한다.
		// 디코딩하기 ㅜ이핸 JwtDecoder가 필요하다
		http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

		return http.build();
	}

	// 데이터베이스 연결을 위한 DataSource Bean 설정
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder() // 장형 데이터베이스를 설정하는 데 사용되는 빌더 클래스 - 별도의 데이터 베이스 서버 필요 없음.
				.setType(EmbeddedDatabaseType.H2).addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION) // 데이터베이스 초기화를
																											// 위해 SQL
																											// 스크립트를 실행
																											// (어딘가에서
																											// 정의된 SQL
																											// 스크립트의 위치를
																											// 나타냄)
				.build();
	}

	// 여러 사용자를 생성 - 메모리에 모든 정보를 생성하다.
	@Bean
	public UserDetailsService userDetailService() {

		var user = User.withUsername("in28minute")
				// .password("{noop}dummy")
				.password("dummy").passwordEncoder(str -> passwordEncoder().encode(str)).roles("USER").build();
		var admin = User.withUsername("admin")
//				.password("{noop}dummy")
				.password("dummy").passwordEncoder(str -> passwordEncoder().encode(str)).roles("ADMIN").build();

		return new InMemoryUserDetailsManager(user, admin);
	}

	// bcrypt 사용 BCryptPasswordEncoder: 강력한 해싱 함수 BCrypt를 사용하는 PasswordEncoder
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// KeyPairGenerator 클래스 사용 - 키쌍 만들기
	@Bean
	public KeyPair keyPair() {

		try {
			// RSA 알고리즘을 위해 인스턴스 받기
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			// 키 사이즈 설정 - 키사이즈가 클수록 보안 수준도 높아진다.
			keyPairGenerator.initialize(2048); // 2048비트 RSA 암호화

			// 키쌍 생성
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}
	
	//Oauth2 의존성에 있는 nimbusds 라이브러리 사용
	@Bean
	public RSAKey rsaKey(KeyPair keyPair) {
		
		//키 쌍 만들기
		return new RSAKey
				.Builder((RSAPublicKey)keyPair.getPublic())
				.privateKey(keyPair.getPrivate())
				.keyID(UUID.randomUUID().toString())
				.build();
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
		
		//a. JWKSet 생성
		var jwkSet = new JWKSet(rsaKey);
		
		//b. JWKSource 생성
		return (jwkSelecotr, context) -> jwkSelecotr.select(jwkSet); 
		
		
	}

	// JWT Decoder 만들기 -nimbus 라이브러리 사용
	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
		
		return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey())
				.build();
	}
	
	

}
