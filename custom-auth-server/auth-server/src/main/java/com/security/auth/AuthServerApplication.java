package com.security.auth;

import com.security.auth.entity.EnumRole;
import com.security.auth.entity.Role;
import com.security.auth.entity.User;
import com.security.auth.repository.RoleRepository;
import com.security.auth.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@SpringBootApplication
@EnableDiscoveryClient
public class AuthServerApplication implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthServerApplication(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApplication.class, args);
    }

    @Override
    public void run(String... args) {
        AddUser();
    }

    public void AddUser() {

        Role r1 = new Role();
        r1.setAuthority(EnumRole.ADMIN);

        Role r2 = new Role();
        r2.setAuthority(EnumRole.USER);

        Role r3 = new Role();
        r3.setAuthority(EnumRole.ACCOUNTS);

        roleRepository.saveAll(List.of(r1, r2, r3));

        User u1 = new User();
        u1.setUsername("test");
        u1.setPassword(passwordEncoder.encode("test"));
        u1.setRoles(List.of(r1,r3));

        User u2 = new User();
        u2.setUsername("test2");
        u2.setPassword(passwordEncoder.encode("test"));
        u2.setRoles(List.of(r1, r2));


        userRepository.saveAll(List.of(u1, u2));
    }
}
