package io.jwt.test.rest;

import org.eclipse.microprofile.auth.LoginConfig;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;

@ApplicationPath("/")
@LoginConfig(authMethod = "MP-JWT", realmName = "MP-JWT")
public class JWTApplication extends Application {
}
