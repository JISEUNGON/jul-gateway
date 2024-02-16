package com.julindang.gateway.filter;

import com.julindang.gateway.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.*;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import reactor.core.publisher.Flux;

import java.nio.charset.StandardCharsets;

@Component
@Slf4j
public class JwtUserFilter extends AbstractGatewayFilterFactory<JwtUserFilter.Config> {
    public JwtUserFilter() {
        super(Config.class);
    }

    @Value("${gateway.host}")
    private String host;

    @Override
    public GatewayFilter apply(final Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            //header 값
            String authorizationHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            // bearer이 아니면 오류
            if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                // 응답 내용 수정
                String modifiedResponse = "JWT Token does not begin with Bearer String.";
                DataBuffer newResponseData = response.bufferFactory().wrap(modifiedResponse.getBytes(StandardCharsets.UTF_8));
                response.getHeaders().setContentLength(modifiedResponse.length());

                log.error("JWT Token does not begin with Bearer String.");

                return response.writeWith(Flux.just(newResponseData));
            }

            // Token, memberId 꺼내기
            String token = authorizationHeader.split(" ")[1];

            // Token 검증
            if (!JwtUtil.validateToken(token)) {
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                // 응답 내용 수정
                String modifiedResponse = "JWT Token is not valid.";
                DataBuffer newResponseData = response.bufferFactory().wrap(modifiedResponse.getBytes(StandardCharsets.UTF_8));
                response.getHeaders().setContentLength(modifiedResponse.length());

                log.error("JWT Token is not valid.");

                return response.writeWith(Flux.just(newResponseData));
            }

            // Token 만료 체크
            if (JwtUtil.isExpired(token)) {
                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                // 응답 내용 수정
                String modifiedResponse = "JWT Token is expired.";
                DataBuffer newResponseData = response.bufferFactory().wrap(modifiedResponse.getBytes(StandardCharsets.UTF_8));
                response.getHeaders().setContentLength(modifiedResponse.length());

                log.error("WT Token is expired.");

                return response.writeWith(Flux.just(newResponseData));
            }

            //token이 디비에 존재하는지 검증 + 권한 검증
            RestTemplate restTemplate = new RestTemplate();

            //header 설
            HttpHeaders headers = new HttpHeaders();

            headers.setContentType(MediaType.APPLICATION_JSON); // Content-Type 헤더 설정
            headers.set("Authorization", "Bearer " + token);

            HttpEntity<String> requestEntity = new HttpEntity<>(null, headers);

            final String tokenResponse = restTemplate.exchange(host, HttpMethod.GET, requestEntity, String.class).getBody();

            if(tokenResponse == null) {
                log.info("role: {}", "ROLE_USER");

                response.setStatusCode(HttpStatus.UNAUTHORIZED);
                // 응답 내용 수정
                String modifiedResponse = "User does not have permission.";
                DataBuffer newResponseData = response.bufferFactory().wrap(modifiedResponse.getBytes(StandardCharsets.UTF_8));
                response.getHeaders().setContentLength(modifiedResponse.length());

                log.error("User does not have permission.");

                return response.writeWith(Flux.just(newResponseData));
            }

            return chain.filter(exchange);
        };
    }

    public static class Config {

    }
}
