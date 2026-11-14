/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.Locale;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.owasp.webgoat.container.i18n.Language;
import org.owasp.webgoat.container.users.UserRepository;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Negative security tests: each one sends a request that must be rejected and checks that the
 * rejection really happens. If the control it covers is removed, the test fails.
 *
 * <ul>
 *   <li>Authorization: {@code WebSecurityConfig} ({@code /service/admin/**}) + {@code
 *       AdminController} ({@code @PreAuthorize})
 *   <li>Authentication: {@code WebSecurityConfig} ({@code anyRequest().authenticated()})
 *   <li>Input validation: {@code UserForm} constraints, {@code UserValidator} and {@code
 *       RegistrationController} ({@code bindingResult.hasErrors()})
 *   <li>Error handling: {@code AdminController#resetPassword} (unknown user returns 404)
 * </ul>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, classes = WebGoat.class)
@TestPropertySource(
    locations = {
      "classpath:/application-webgoat.properties",
      "classpath:/application-webgoat-test.properties"
    })
class NegativeSecurityTest {

  @Autowired private WebApplicationContext wac;
  @Autowired private UserRepository userRepository;
  @MockitoBean private Language language;
  @MockitoBean private ClientRegistrationRepository clientRegistrationRepository;

  private MockMvc mockMvc;

  @BeforeEach
  void setUp() {
    when(language.getLocale()).thenReturn(Locale.getDefault());
    mockMvc = MockMvcBuilders.webAppContextSetup(wac).apply(springSecurity()).build();
  }

  @Test
  void regularUserCannotUseAdminEndpoints() throws Exception {
    WebGoatUser regular = new WebGoatUser("regularuser", "password", WebGoatUser.ROLE_USER);

    mockMvc.perform(get("/service/admin/users").with(user(regular))).andExpect(status().isForbidden());
    mockMvc
        .perform(post("/service/admin/users/regularuser/reset-password").with(user(regular)))
        .andExpect(status().isForbidden());
  }

  @Test
  void anonymousRequestToProtectedPageIsRejected() throws Exception {
    // Browser navigation: redirected to the login page
    mockMvc
        .perform(get("/welcome.mvc"))
        .andExpect(status().is3xxRedirection())
        .andExpect(redirectedUrl("/login"));

    // AJAX call: 401 instead of a redirect
    mockMvc
        .perform(get("/service/lessonmenu.mvc").header("x-requested-with", "XMLHttpRequest"))
        .andExpect(status().isUnauthorized());
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource({
    "username too short,       abc,         password1, password1",
    "username with bad chars,  Bad_User!,   password1, password1",
    "passwords do not match,   validuser1,  password1, password2",
    "password too short,       validuser2,  abc,       abc"
  })
  void registrationWithInvalidDataIsRejected(
      String caseName, String username, String password, String matchingPassword) throws Exception {
    mockMvc
        .perform(
            post("/register.mvc")
                .param("username", username)
                .param("password", password)
                .param("matchingPassword", matchingPassword)
                .param("agree", "agree"))
        .andExpect(status().isOk())
        .andExpect(view().name("registration"))
        .andExpect(model().attributeHasErrors("userForm"));

    assertThat(userRepository.findByUsername(username)).isNull();
  }

  @Test
  void resetPasswordOfUnknownUserReturnsControlled404() throws Exception {
    WebGoatUser admin = new WebGoatUser("adminuser", "password", WebGoatUser.ROLE_ADMIN);

    mockMvc
        .perform(post("/service/admin/users/does-not-exist/reset-password").with(user(admin)))
        .andExpect(status().isNotFound())
        .andExpect(content().string(""));
  }
}
