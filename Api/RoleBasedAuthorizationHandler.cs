using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace Api;

class RoleBasedAuthorizationHandler : AuthorizationHandler<RoleBasedRequirement>
{	
	// this is a handler for authorization requirement (RoleBasedRequirement)
	// 
	protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, RoleBasedRequirement roleBasedRequirement)
	{
		if (context.User.Identity is not { IsAuthenticated: true })
		{
			context.Fail(new AuthorizationFailureReason(this, "User is not authenticated"));
			return Task.CompletedTask;
		}

		var role = context.User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.Role)?.Value;

		if (role is null)
		{
			context.Fail(new AuthorizationFailureReason(this,
				"User has no role")); // which should never happen because we add client role by default to all users if they don't have any role
			return Task.CompletedTask;
		}

		var roles = role.Split(',', StringSplitOptions.RemoveEmptyEntries);

		var isAuthorized = roles.Any(x => x == roleBasedRequirement.RoleName);

		if (isAuthorized)
		{
			context.Succeed(roleBasedRequirement);
		}
		else
		{
			context.Fail(new AuthorizationFailureReason(this, "User is not authorized"));
		}
		
		return Task.CompletedTask;
	}
}