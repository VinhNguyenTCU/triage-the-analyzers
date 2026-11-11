package team.projectpulse.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import team.projectpulse.student.Student;
import team.projectpulse.user.MyUserPrincipal;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class AuthServiceTest {

    @Test
    void createLoginInfoRejectsAnAccountWithMissingRoles() {
        Student student = new Student();
        student.setRoles(null);
        MyUserPrincipal principal = new MyUserPrincipal(student);
        var authentication = UsernamePasswordAuthenticationToken.authenticated(
                principal, null, principal.getAuthorities());
        JwtProvider jwtProvider = mock(JwtProvider.class);
        AuthService authService = new AuthService(jwtProvider, null, null);

        assertThatThrownBy(() -> authService.createLoginInfo(authentication))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Account has no assigned role");
        verifyNoInteractions(jwtProvider);
    }
}
