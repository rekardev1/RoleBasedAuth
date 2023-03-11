using System.Security.Claims;
using Api;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

const string authSchema = "cookie";

builder.Services.AddSingleton<IAuthorizationHandler, RoleBasedAuthorizationHandler>();
builder.Services.AddAuthentication(authSchema).AddCookie(authSchema, options =>
{
	options.LoginPath = "/login";
	options.AccessDeniedPath = "/denied";
});

builder.Services.AddAuthorization(options =>
{
	// this is where we add policies for authorization
	// we add policies for each role
	// and we add requirement for each policy 
	// which is a RoleBasedRequirement with role name
	// this means when we add this policy to endpoint, it will require user to have this role to access this endpoint
	foreach (var role in Enum.GetNames<Role>())
	{
		options.AddPolicy(role, policyBuilder => policyBuilder.AddRequirements(new RoleBasedRequirement(role)).RequireAuthenticatedUser());
	}
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/signin", ([FromQuery] string? username, [FromQuery] Role[]? roles, HttpContext context) =>
{
	var claims = new List<Claim> { new(ClaimTypes.Name, username ?? "Bot") };

	if (roles is { Length: > 0 })
	{
		claims.Add(new Claim(ClaimTypes.Role, string.Join(",", roles)));
	}
	else
	{
		claims.Add(new Claim(ClaimTypes.Role, nameof(Role.Client)));
	}

	context.SignInAsync(new ClaimsPrincipal(new ClaimsIdentity(claims, authSchema)));
	return "signed in as " + username + " with roles: " + string.Join(",", roles ?? Array.Empty<Role>());
});

app.MapGet("/client", () => "client page").RequireAuthorization(nameof(Role.Client)); // this will require user to have client role to access this endpoint
app.MapGet("/admin", () => "admin page").RequireAuthorization(nameof(Role.Admin));
app.MapGet("/support", () => "support page").RequireAuthorization(nameof(Role.Support));

app.MapGet("/signout", (HttpContext context) =>
{
	context.SignOutAsync();
	return "signed out";
});

app.MapGet("/login", () => "to login go to /signin?username=yourname&roles=Admin&roles=Support");
app.MapGet("/denied", () => "access denied");

app.Run();