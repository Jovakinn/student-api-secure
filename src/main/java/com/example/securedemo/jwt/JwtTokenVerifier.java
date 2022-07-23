package com.example.securedemo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static java.util.stream.Collectors.toSet;

public class JwtTokenVerifier extends OncePerRequestFilter {
    private final SecretKey secretKey;
    private final JwtConfig jwtConfig;

    public JwtTokenVerifier(SecretKey secretKey, JwtConfig jwtConfig) {
        this.secretKey = secretKey;
        this.jwtConfig = jwtConfig;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());
        if (checkWhetherToContinue(request, response, filterChain, authorizationHeader)) return;
        String token = authorizationHeader.replace( jwtConfig.getTokenPrefix(), "");
        try {
            var claimsJws = generateJwtClaims(token);
            Claims body = claimsJws.getBody();
            String username = body.getSubject();
            List<Map<String, String>> authorities = getAuthorities(body);
            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = generateSimpleGrantedAuthority(authorities);
            Authentication authentication = generateAuthentication(username, simpleGrantedAuthorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException e) {
            throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
        }
        filterChain.doFilter(request, response);
    }

    private List<Map<String, String>> getAuthorities(Claims body) {
        return (List<Map<String, String>>) body.get("authorities");
    }

    private Authentication generateAuthentication(String username, Set<SimpleGrantedAuthority> simpleGrantedAuthorities) {
        return new UsernamePasswordAuthenticationToken(
                username,
                null,
                simpleGrantedAuthorities
        );
    }

    private Set<SimpleGrantedAuthority> generateSimpleGrantedAuthority(List<Map<String, String>> authorities) {
        return authorities.stream()
                .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                .collect(toSet());
    }

    private Jwt<Header, Claims> generateJwtClaims(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJwt(token);
    }

    private boolean checkWhetherToContinue(HttpServletRequest request,
                                           HttpServletResponse response,
                                           FilterChain filterChain,
                                           String authorizationHeader) throws IOException, ServletException {
        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);
            return true;
        }
        return false;
    }
}
