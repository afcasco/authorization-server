package dev.afcasco.authorizationserver.security;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import dev.afcasco.authorizationserver.user.User;
import dev.afcasco.authorizationserver.user.UserRepository;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated()).formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(UserRepository userRepository) {
        return username -> {
            User user = userRepository.findByUsername(username);
            if (user == null) {
                throw new UsernameNotFoundException("user not found");
            }
            return user;
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

// Oauth login url
// http://localhost:9000/oauth2/authorize?response_type=code&client_id=fct-finder-client&redirect_uri=http://127.0.0.1:9090/login/oauth2/code/fct-finder-client&scope=user


// Obtjain jwt token
// curl 127.0.0.1:9000/oauth2/token -H"Content-type: application/x-www-form-urlencoded" -d"grant_type=authorization_code" -d"redirect_uri=http://127.0.0.1:9090/login/oauth2/code/fct-finder-client" -d"code=QZusSM2g-gLacOV0li8BJOG9c5ym752-JmICmDs876YhNqhQrHQIDyeJCPwozMb8ERUBzIXLSama9EBffNwx2y54Y4dVn0iMQ7JSF54WSr9CiEJSze2FfLVxXfqoL2ib" -u fct-finder-client:super-secret

// Refresh token with curl
// curl 127.0.0.1:9000/oauth2/token -H"Content-type: application/x-www-form-urlencoded" -d"grant_type=refresh_token&refresh_token=oIE4fus9utRshsLP3E0EILNnuZ2RvLCHX8mzyhRJR6ZNfBB6pvH3RKEaAs2Kq-SvbDc1CKPw-FDM1LVDGLV7rOwJlfCKuzllfJjdnvWjAVbI-8OCrOc2qiSQamcylt0a" -d"redirect_uri=http://127.0.0.1:9090/login/oauth2/code/fct-finder-client" -u fct-finder-client:super-secret

    @Bean
    public RegisteredClientRepository repository(PasswordEncoder passwordEncoder) {
        RegisteredClient registeredClient =
                RegisteredClient.withId(UUID.randomUUID().toString())
                        .clientId("fct-finder-client")
                        .clientSecret(passwordEncoder.encode("super-secret"))
                        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                        .redirectUri("http://127.0.0.1:9090/login/oauth2/code/fct-finder-client")
                        .scope(OidcScopes.OPENID)
                        .scope("modifyUsers")
                        .scope("modifyCompanies")
                        .scope("user")
                        .scope("admin")
                        .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                        .build();
        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAKey rsaKey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);

    }

    private RSAKey generateRsa() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();

    }

    private KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    @Bean
    public ApplicationRunner dataLoader(UserRepository repository) {
        return args -> {
            repository.save(new User(0L, "afcasco", "afcasco@gmail.com", passwordEncoder().encode("test123")));
        };

    }


}
