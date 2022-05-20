package com.ha.security;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Handles requests for the application home page.
 */
@Controller
public class HomeController {

	@Autowired
	private InMemoryTokenStore tokenStore;

	@RequestMapping(value = { "/" }, method = RequestMethod.GET)
	public String welcomePage() {
		return "index";

	}

	@RequestMapping(value = "/admin", method = RequestMethod.GET, produces = { MediaType.APPLICATION_JSON_VALUE })
	@ResponseStatus(value = HttpStatus.OK)
	@ResponseBody
	public ResponseDto adminPage() {
		return new ResponseDto("Can Access Admin");
	}

	@RequestMapping(value = "/login", method = RequestMethod.POST, produces = { MediaType.APPLICATION_JSON_VALUE })
	@ResponseStatus(value = HttpStatus.OK)
	@ResponseBody
	public ResponseDto login(@RequestBody UserLoginDto loginDto) {
		String userName = loginDto.getUserName();
		String password = loginDto.getPassword();
		if (StringUtils.hasText(userName) && StringUtils.hasText(password)
				&& userName.equals("hr") && password.equals("hr")) {
			ArrayList<GrantedAuthority> objAuthorities = new ArrayList<GrantedAuthority>();
			SimpleGrantedAuthority objAuthority = new SimpleGrantedAuthority(
					"ROLE_ADMIN");
			objAuthorities.add(objAuthority);
			User user = new User(userName, password, objAuthorities);
			return new ResponseDto(this.tokenStore.generateAccessToken(user));
		} else {
			return new ResponseDto("Not Valid User");
		}
	}
}
