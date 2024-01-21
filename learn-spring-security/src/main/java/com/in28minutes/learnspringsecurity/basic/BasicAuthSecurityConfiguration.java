package com.in28minutes.learnspringsecurity.basic;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;


//CSRF 해제하기
@Configuration
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
}
