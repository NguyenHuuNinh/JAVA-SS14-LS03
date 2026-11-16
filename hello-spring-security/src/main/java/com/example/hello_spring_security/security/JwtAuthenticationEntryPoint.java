
package com.example.hello_spring_security.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        // 1. Thiết lập mã lỗi 401 Unauthorized và kiểu dữ liệu trả về là JSON
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        // 2. Lấy chi tiết lỗi Token được đính kèm từ JwtAuthenticationFilter (nếu có)
        String jwtError = (String) request.getAttribute("jwt_error");
        String message = (jwtError != null)
                ? jwtError
                : "Unauthorized: Token không hợp lệ hoặc đã hết hạn";

        // 3. Tạo body JSON chuẩn hóa
        Map<String, Object> body = new HashMap<>();
        body.put("code", 401);
        body.put("status", "FAIL");
        body.put("message", message);

        // 4. Ghi JSON ra response
        ObjectMapper mapper = new ObjectMapper();
        mapper.writeValue(response.getOutputStream(), body);
    }
}