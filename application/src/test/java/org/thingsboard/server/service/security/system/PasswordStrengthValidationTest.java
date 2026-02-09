/**
 * Copyright © 2016-2026 The Thingsboard Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.thingsboard.server.service.security.system;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.thingsboard.rule.engine.api.MailService;
import org.thingsboard.server.dao.audit.AuditLogService;
import org.thingsboard.server.dao.settings.AdminSettingsService;
import org.thingsboard.server.dao.settings.SecuritySettingsService;
import org.thingsboard.server.dao.user.UserService;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(MockitoJUnitRunner.class)
public class PasswordStrengthValidationTest {

    @Mock
    private AdminSettingsService adminSettingsService;
    @Mock
    private BCryptPasswordEncoder encoder;
    @Mock
    private UserService userService;
    @Mock
    private MailService mailService;
    @Mock
    private AuditLogService auditLogService;
    @Mock
    private SecuritySettingsService securitySettingsService;

    private DefaultSystemSecurityService systemSecurityService;

    @Before
    public void setUp() {
        systemSecurityService = new DefaultSystemSecurityService(
                adminSettingsService, encoder, userService, mailService,
                auditLogService, securitySettingsService);
    }

    @Test
    public void testStrongPassword() {
        runTest("testStrongPassword", "Abcd1234!", true);
    }

    @Test
    public void testTooShort() {
        runTest("testTooShort", "Ab1!a", false);
    }

    @Test
    public void testMissingUppercase() {
        runTest("testMissingUppercase", "abcd1234!", false);
    }

    @Test
    public void testMissingLowercase() {
        runTest("testMissingLowercase", "ABCD1234!", false);
    }

    @Test
    public void testMissingDigit() {
        runTest("testMissingDigit", "Abcdefgh!", false);
    }

    private void runTest(String testName, String input, boolean expectedResult) {
        boolean actualResult = systemSecurityService.isStrongPassword(input);
        String status = (actualResult == expectedResult) ? "PASS" : "FAIL";
        System.out.println(String.format("%s | Entrée: \"%s\" | Résultat attendu: %s | Résultat réel: %s | %s",
                testName, input, expectedResult, actualResult, status));
        assertThat(actualResult).isEqualTo(expectedResult);
    }
}
