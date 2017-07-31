package com.example.rest;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.mobile.device.Device;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.example.models.JwtAuthenticationRequest;
import com.example.models.JwtAuthenticationResponse;
import com.example.models.JwtUser;
import com.example.security.JwtTokenUtil;
import com.example.security.MemberServiceImpl;
import com.example.security.WebAuthenticationDetailsSourceImpl;

@RestController
public class AuthenticationRestController {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	@Autowired
	private MemberServiceImpl userDetailsService;

	@RequestMapping(value = "/auth", method = RequestMethod.POST)
	public ResponseEntity<?> createAuthenticationToken(HttpServletRequest request, Device device)
			throws AuthenticationException {

		WebAuthenticationDetailsSourceImpl webAuthenticationDetailsSourceImpl = new WebAuthenticationDetailsSourceImpl();
		JwtAuthenticationRequest authenticationRequest = webAuthenticationDetailsSourceImpl.buildDetails(request);
		UsernamePasswordAuthenticationToken token1 = new UsernamePasswordAuthenticationToken(
				authenticationRequest.getUsername(), authenticationRequest.getPassword());

		token1.setDetails(authenticationRequest);
		Authentication authentication = authenticationManager.authenticate(token1);
		SecurityContextHolder.getContext().setAuthentication(authentication);

		JwtUser userDetails = userDetailsService.loadUserByUsername(authenticationRequest.getUsername());
		final String token = jwtTokenUtil.generateToken(userDetails, device);

		return ResponseEntity.ok(new JwtAuthenticationResponse(token));
	}
}
