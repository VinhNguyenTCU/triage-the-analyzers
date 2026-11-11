package team.projectpulse.security;

import team.projectpulse.instructor.Instructor;
import team.projectpulse.instructor.converter.InstructorToInstructorDtoConverter;
import team.projectpulse.instructor.dto.InstructorDto;
import team.projectpulse.student.Student;
import team.projectpulse.student.converter.StudentToStudentDtoConverter;
import team.projectpulse.student.dto.StudentDto;
import team.projectpulse.user.MyUserPrincipal;
import team.projectpulse.user.PeerEvaluationUser;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class AuthService {

    private final JwtProvider jwtProvider;

    private final StudentToStudentDtoConverter studentToStudentDtoConverter;
    private final InstructorToInstructorDtoConverter instructorToInstructorDtoConverter;


    public AuthService(JwtProvider jwtProvider, StudentToStudentDtoConverter studentToStudentDtoConverter, InstructorToInstructorDtoConverter instructorToInstructorDtoConverter) {
        this.jwtProvider = jwtProvider;
        this.studentToStudentDtoConverter = studentToStudentDtoConverter;
        this.instructorToInstructorDtoConverter = instructorToInstructorDtoConverter;
    }

    public Map<String, Object> createLoginInfo(Authentication authentication) {
        // Create user info.
        if (!(authentication.getPrincipal() instanceof MyUserPrincipal principal)) {
            throw new AccessDeniedException("Login requires a username and password");
        }
        PeerEvaluationUser peerEvaluationUser = principal.getPeerEvaluationUser();
        String roles = peerEvaluationUser.getRoles();
        if (roles == null || roles.isBlank()) {
            throw new AccessDeniedException("Account has no assigned role");
        }

        Map<String, Object> loginResultMap = new HashMap<>();

        if ("student".equals(roles)) {
            StudentDto studentDto = this.studentToStudentDtoConverter.convert((Student) peerEvaluationUser);
            // Create a JWT.
            String token = this.jwtProvider.createToken(authentication, peerEvaluationUser.getId());
            loginResultMap.put("userInfo", studentDto);
            loginResultMap.put("token", token);
        } else if (roles.contains("instructor")) {
            InstructorDto instructorDto = this.instructorToInstructorDtoConverter.convert((Instructor) peerEvaluationUser);
            // Create a JWT.
            String token = this.jwtProvider.createToken(authentication, peerEvaluationUser.getId());
            loginResultMap.put("userInfo", instructorDto);
            loginResultMap.put("token", token);
        }
        return loginResultMap;
    }

}
