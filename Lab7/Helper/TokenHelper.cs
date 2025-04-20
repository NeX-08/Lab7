using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

public static class TokenHelper
{
    public static string SecretKey = string.Empty;
    public static string Issuer = string.Empty;
    public static string Audience = string.Empty;

    public static object GenerateToken(IdentityUser user, List<string> roles)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>();

        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var token = new JwtSecurityToken(
            issuer: Issuer,
            audience: Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddSeconds(30),
            signingCredentials: creds
        );
        var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

        return new
        {
            token = jwtToken,
            email = user.Email
        };
    }
    public static object GenerateToken(IdentityUser user)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: Issuer,
            audience: Audience,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds
        );
        var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

        return new
        {
            token = jwtToken,
            email = user.Email
        };
    }
}