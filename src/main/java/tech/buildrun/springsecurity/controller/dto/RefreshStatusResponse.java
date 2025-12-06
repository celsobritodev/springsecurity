package tech.buildrun.springsecurity.controller.dto;

import tech.buildrun.springsecurity.services.TokenService.RefreshStatus;

public record RefreshStatusResponse(
	    RefreshStatus status,
	    String mensagem
	) {}