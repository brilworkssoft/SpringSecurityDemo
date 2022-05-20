package com.ha.security;

import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.core.userdetails.UserDetails;

/**
 * Implementation of token services that stores tokens in memory.
 * 
 * @author HR
 */
public class InMemoryTokenStore {
	private ConcurrentHashMap<String, UserDetails> token = new ConcurrentHashMap<String, UserDetails>();

	public InMemoryTokenStore() {

	}

	public void removeToken(String accessToken) {
		if (this.token.containsKey(accessToken)) {
			this.token.remove(accessToken);
		}
	}

	public UserDetails readAccessToken(String accessToken) {

		if (this.token.containsKey(accessToken)) {
			return this.token.get(accessToken);
		} else {
			return null;
		}
	}

	public String generateAccessToken(UserDetails user) {
		String accessToken = null;
		accessToken = SecurityUtils.getAuthenticationTokenOrSecret(user
				.getUsername());
		this.token.put(accessToken, user);
		return accessToken;
	}

}
