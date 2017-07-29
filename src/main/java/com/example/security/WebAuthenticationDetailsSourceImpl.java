package com.example.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import com.example.models.JwtAuthenticationRequest;
import com.google.gson.Gson;

@Component
public class WebAuthenticationDetailsSourceImpl
		implements AuthenticationDetailsSource<HttpServletRequest, JwtAuthenticationRequest> {

	@Override
	public JwtAuthenticationRequest buildDetails(HttpServletRequest context) {
		Gson gson = new Gson();
		String json = new String();
		String output = new String();
		BufferedReader br;
		StringBuffer buffer = new StringBuffer(16384);
		JwtAuthenticationRequest jwtAuthenticationRequest = new JwtAuthenticationRequest();

		try {
			br = new BufferedReader(new InputStreamReader(context.getInputStream()));
			while ((output = br.readLine()) != null) {
				buffer.append(output);
			}

			json = buffer.toString();
			JwtAuthenticationRequest myBean = gson.fromJson(json, JwtAuthenticationRequest.class);
			jwtAuthenticationRequest = myBean;
		} catch (IOException e) {
			e.printStackTrace();
		}

		return jwtAuthenticationRequest;
	}
}
