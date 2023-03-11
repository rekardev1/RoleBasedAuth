using Microsoft.AspNetCore.Authorization;

namespace Api;

class RoleBasedRequirement : IAuthorizationRequirement 
{
	// this is a requirement for authorization handler
	public string RoleName { get; }

	public RoleBasedRequirement(string roleName)
	{
		RoleName = roleName;
	}
}