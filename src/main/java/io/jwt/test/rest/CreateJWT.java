package io.jwt.test.rest;

import io.jwt.test.util.SecurityUtils;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Response;

@Path("/")
public class CreateJWT {

  @Inject
  private SecurityUtils secUtils;

  @GET
  @Produces("text/plain")
  @Path("/createJWT")
  public Response createJWT() {
    try {
      String token = secUtils.generateJwt();
      return Response.ok(token).build();
    } catch (Exception e) {
      e.printStackTrace();
      return Response.status(Response.Status.INTERNAL_SERVER_ERROR).build();
    }
  }
}
