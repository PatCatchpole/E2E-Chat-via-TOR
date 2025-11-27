package br.com.spectre.spectrechat.config;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import java.io.IOException;

@Component
public class InternalTokenFilter implements Filter {

    private static final String INTERNAL_TOKEN = "super-secreto-local";

    @Override
    public void doFilter(
            ServletRequest request,
            ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        String path = req.getRequestURI();

        if (path.startsWith("/internal/")) {
            String token = req.getHeader("X-Internal-Token");
            if (!INTERNAL_TOKEN.equals(token)) {
                ((HttpServletResponse) response).sendError(401, "Unauthorized");
                return;
            }
        }

        chain.doFilter(request, response);
    }
}
