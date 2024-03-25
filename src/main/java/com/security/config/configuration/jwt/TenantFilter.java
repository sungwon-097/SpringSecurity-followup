package com.security.config.configuration.jwt;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.nio.file.AccessDeniedException;

public class TenantFilter implements Filter {

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    String tenantId = request.getHeader("X-Tenant-Id");
    boolean hasAccess = true;
    if (hasAccess) {
      filterChain.doFilter(request, response);
      return;
    }
    throw new AccessDeniedException("Access denied");
  }

}