


package com.in28minutes.learnspringsecurity.basic;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


//CSRF 해제하기
//@Configuration
public class BasicAuthSecurityConfiguration {

	@Bean
	SecurityFilterChain SecurityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests(
				auth -> {
						auth.anyRequest().authenticated();
				});
		http.sessionManagement(
				session -> 
					session.sessionCreationPolicy(SessionCreationPolicy.STATELESS) //STATELESS: 세션사용하지 않는다는뜻.
				);
		//http.formLogin(withDefaults());
		http.httpBasic(withDefaults());
		
		//csrf 해제
		http.csrf().disable();
		
		return http.build();
	}
	
	//여러 사용자를 생성 - 메모리에 모든 정보를 생성하다.
	@Bean
	public UserDetailsService userDetailService() {
		
		var user = User.withUsername("in28minute")
			//.password("{noop}dummy")
			.password("dummy")
			.passwordEncoder(str -> passwordEncoder().encode(str))
			.roles("USER")
			.build();
		var admin = User.withUsername("admin")
//				.password("{noop}dummy")
				.password("dummy")
				.passwordEncoder(str -> passwordEncoder().encode(str))
				.roles("ADMIN")
				.build();
	
		
		return new InMemoryUserDetailsManager(user, admin);
	}
	
	//bcrypt 사용 BCryptPasswordEncoder: 강력한 해싱 함수 BCrypt를 사용하는 PasswordEncoder
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
