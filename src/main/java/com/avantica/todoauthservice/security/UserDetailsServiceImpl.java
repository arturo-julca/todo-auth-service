package com.avantica.todoauthservice.security;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.avantica.todoauthservice.model.AppUser;
import com.netflix.hystrix.contrib.javanica.annotation.HystrixCommand;

@Service
public class UserDetailsServiceImpl implements UserDetailsService  {
	
	@Autowired
	private BCryptPasswordEncoder encoder;

	@Autowired
	private RestTemplate restTemplate;
	
	@Value("${reminder.server.url}")
	private String SERVICE_URL;
	
	@Override	
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser appUser = getUserFromRest(username);
		if(appUser!=null){
			List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList(
					"ROLE_" + appUser.getRole());
			return new User(appUser.getUsername(), encoder.encode(appUser.getPassword()), grantedAuthorities);
		}else{
			throw new UsernameNotFoundException("Username: " + username + " not found");
		}
	}
	
	@HystrixCommand(fallbackMethod = "fallbackUser")	
	private AppUser getUserFromRest(String username){
		return restTemplate.getForObject(SERVICE_URL+"/username/"+username, AppUser.class);
	}
	
	public AppUser fallbackUser(String username, Throwable hystrixCommand){
		return null;
	}
}