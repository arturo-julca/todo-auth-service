package com.avantica.todoauthservice.security;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
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

@Service   // It has to be annotated with @Service.
public class UserDetailsServiceImpl implements UserDetailsService  {
	
	@Autowired
	private BCryptPasswordEncoder encoder;

	@Autowired
	private RestTemplate restTemplate;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		//RestTemplate restTemplate = new RestTemplate();
		AppUser appUser = restTemplate.getForObject("http://user-service/username/"+username, AppUser.class);
		if(appUser!=null){
			List<GrantedAuthority> grantedAuthorities = AuthorityUtils.commaSeparatedStringToAuthorityList(
					"ROLE_" + appUser.getRole());
			return new User(appUser.getUsername(), encoder.encode(appUser.getPassword()), grantedAuthorities);
		}else{
			throw new UsernameNotFoundException("Username: " + username + " not found");
		}
		
//		// hard coding the users. All passwords must be encoded.
//		final List<AppUser> users = Arrays.asList(
//			new AppUser(1, "omar", encoder.encode("12345"), "USER"),
//			new AppUser(2, "admin", encoder.encode("12345"), "ADMIN")
//		);
//		
//
//		for(AppUser appUser: users) {
//			if(appUser.getUsername().equals(username)) {
//				
//				// Remember that Spring needs roles to be in this format: "ROLE_" + userRole (i.e. "ROLE_ADMIN")
//				// So, we need to set it to that format, so we can verify and compare roles (i.e. hasRole("ADMIN")).
//				List<GrantedAuthority> grantedAuthorities = AuthorityUtils
//		                	.commaSeparatedStringToAuthorityList("ROLE_" + appUser.getRole());
//				
//				// The "User" class is provided by Spring and represents a model class for user to be returned by UserDetailsService
//				// And used by auth manager to verify and check user authentication.
//				return new User(appUser.getUsername(), appUser.getPassword(), grantedAuthorities);
//			}
//		}
		
		// If user not found. Throw this exception.
		//throw new UsernameNotFoundException("Username: " + username + " not found");
	}
}