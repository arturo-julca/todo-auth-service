package com.avantica.todoauthservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.circuitbreaker.EnableCircuitBreaker;
import org.springframework.cloud.client.loadbalancer.LoadBalanced;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
@EnableEurekaClient 		// Enable eureka client.
@EnableCircuitBreaker 	// Enable circuit breakers
@EnableWebSecurity
public class TodoAuthServiceApplication {

	public static void main(String[] args) {
		SpringApplication.run(TodoAuthServiceApplication.class, args);
	}
}

@Configuration
class RestTemplateConfig {
	
	// Create a bean for restTemplate to call services
	@Bean
	@LoadBalanced		// Load balance between service instances running at different ports.
	public RestTemplate restTemplate() {
	    return new RestTemplate();
	}
	
	
}