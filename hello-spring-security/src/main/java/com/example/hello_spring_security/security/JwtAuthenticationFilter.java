package com.example.hello_spring_security.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private UserDetailServiceCustom userDetailServiceCustom;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            // 1. Lấy chuỗi JWT từ Header Authorization (dạng Bearer <token>)
            String jwt = getJwtFromRequest(request);

            // 2. Validate Token (Check chữ ký, check hết hạn)
            if (StringUtils.hasText(jwt) && jwtProvider.validateToken(jwt)) {
                // 3. Lấy username từ Token -> Load UserDetails
                String username = jwtProvider.getUsernameFromToken(jwt);
                UserDetails userDetails = userDetailServiceCustom.loadUserByUsername(username);

                // 4. Tạo UsernamePasswordAuthenticationToken và gán vào SecurityContext
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        } catch (Exception ex) {
            System.out.println("Không thể thiết lập xác thực người dùng: " + ex.getMessage());
        }

        // Cho phép request đi tiếp tới các Filter hoặc Controller tiếp theo
        filterChain.doFilter(request, response);
    }

    // Hàm hỗ trợ bóc tách chuỗi token sau chữ "Bearer "
    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}