package com.d4d.springgcppoc;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class SpringGcpPocApplicationTests {

	@Test
	void testClassicToken() {
		ClassicTokenVerifier cv = new ClassicTokenVerifier();
		assertThat(cv.verifyToken("Hello World!")).isEqualTo(true);
	}

}
