package com.example.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.models.JwtUser;

@Service("userDetailsService")
public class MemberServiceImpl implements UserDetailsService {

	private static final PasswordEncoder BCRYPT = new BCryptPasswordEncoder();

	@Value("${security.user.name}")
	private String hardcodedUser;

	@Value("${security.user.password}")
	private String password;

	@Override
	public JwtUser loadUserByUsername(String username) throws UsernameNotFoundException {
		String hardcodedPassword = BCRYPT.encode(password);
		if (username.equals(hardcodedUser) == false) {
			throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
		} else {
			SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority("ROLE_USER");
			List<GrantedAuthority> grantedAuthorityList = new ArrayList<GrantedAuthority>();
			grantedAuthorityList.add(simpleGrantedAuthority);
			return new JwtUser(hardcodedUser, hardcodedPassword, grantedAuthorityList);
		}
	}

}
