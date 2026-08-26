package br.com.spectre.spectrechat.config;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Guards /internal/** with a shared token.
 *
 * Three things changed: the token comes from configuration instead of being a
 * literal in the source (it was committed, and printed in the README); the
 * comparison is constant-time; and the application refuses to start without a
 * token rather than silently defaulting to a known one.
 */
@Component
public class InternalTokenFilter implements Filter {

    private static final String HEADER = "X-Internal-Token";
    private final byte[] expectedToken;

    public InternalTokenFilter(@Value("${spectre.internal-token:}") String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalStateException(
                    "spectre.internal-token is not set. Provide it via the "
                    + "SPECTRE_INTERNAL_TOKEN environment variable; there is no default.");
        }
        this.expectedToken = token.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;

        // getServletPath() is already normalised by the container, so "/./internal"
        // and "//internal" cannot slip past the prefix test.
        String path = req.getServletPath();

        if (path != null && path.startsWith("/internal/")) {
            String provided = req.getHeader(HEADER);
            if (!matches(provided)) {
                HttpServletResponse res = (HttpServletResponse) response;
                res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
                return;
            }
        }

        chain.doFilter(request, response);
    }

    private boolean matches(String provided) {
        if (provided == null) {
            return false;
        }
        return MessageDigest.isEqual(provided.getBytes(StandardCharsets.UTF_8), expectedToken);
    }
}
