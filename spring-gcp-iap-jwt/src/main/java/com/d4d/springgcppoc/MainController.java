package com.d4d.springgcppoc;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {
    @Autowired
    AuthorizationService authorizationService;

    @GetMapping("/")
    public ResponseEntity<String> home() {
        String content = "<html>"
                        + "<h1>Please login</h1>"
                        + "<p><a href=\"admin\">login</a></p>"
                        + "</html>";
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.setContentType(MediaType.TEXT_HTML);

        return new ResponseEntity<String>(content, responseHeaders, HttpStatus.NOT_FOUND);
    }
    @GetMapping("/admin")
    public ResponseEntity<String> index(@RequestHeader(value = "x-goog-iap-jwt-assertion", required = false) String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isEmpty()) {
            return new ResponseEntity<>("Authorized header x-goog-iap-jwt-assertion required to get access to this endpoint", HttpStatus.UNAUTHORIZED);
        }

        String jwt = authorizationHeader.trim();
        try {
            String subject = authorizationService.getSubject(jwt);
            return new ResponseEntity<>("Hello, " + subject + "!", HttpStatus.OK);
        } catch (UnauthorizedException exception) {
            return new ResponseEntity<>(String.format("Invalid JWT: %s", exception.getMessage()), HttpStatus.UNAUTHORIZED);
        }
    }
}
