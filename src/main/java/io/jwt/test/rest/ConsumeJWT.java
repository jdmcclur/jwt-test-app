package io.jwt.test.rest;

import org.eclipse.microprofile.jwt.JsonWebToken;

import jakarta.annotation.security.RolesAllowed;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;

@Path("/")
@ApplicationScoped
public class ConsumeJWT {

  @Inject
  JsonWebToken jwt;

  @GET
  @Path("/consumeJWT")
  @Produces("text/plain")
  @RolesAllowed({"group"})
  public Response consumeJWT() {
    try {
      return Response.ok(jwt.getSubject()).build();
    } catch (Exception e) {
      e.printStackTrace();
      return Response.status(Status.INTERNAL_SERVER_ERROR).build();
    }
  }
}
