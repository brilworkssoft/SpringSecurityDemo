package com.ha.security;

public class ResponseDto {
	public ResponseDto() {

	}

	public ResponseDto(String message) {
		this.message = message;
	}

	private String message;

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

}
