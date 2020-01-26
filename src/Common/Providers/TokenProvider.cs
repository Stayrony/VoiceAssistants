using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Common.Models;
using Common.Options;
using Common.Providers.Contract;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Common.Providers
{
    public class TokenProvider : ITokenProvider
    {
        private readonly TokenInfo _tokenInfo;

        public TokenProvider(IOptions<JwtTokenOptions> jwtTokenOptions)
        {
            _tokenInfo = new TokenInfo
            {
                Audience = jwtTokenOptions.Value.Audience,
                Issuer = jwtTokenOptions.Value.Issuer,
                IssuerSecurityKey = jwtTokenOptions.Value.IssuerSecurityKey,
                Lifetime = jwtTokenOptions.Value.Lifetime,
                LifetimeExternal = jwtTokenOptions.Value.LifetimeExternal,
                ValidateAudience = jwtTokenOptions.Value.ValidateAudience,
                ValidateIssuer = jwtTokenOptions.Value.ValidateIssuer,
                ValidateLifetime = jwtTokenOptions.Value.ValidateLifetime,
                ValidateIssuerSigningKey = jwtTokenOptions.Value.ValidateIssuerSigningKey,
                Authority = jwtTokenOptions.Value.Authority,
            };
        }

        /// <summary>
        /// Gets the token info.
        /// </summary>
        /// <value>The token info.</value>
        public TokenInfo TokenInfo => _tokenInfo;

        /// <summary>
        /// Creates the token.
        /// </summary>
        /// <returns>The token.</returns>
        /// <param name="claims">Claims.</param>
        public AccessTokenModel CreateAccessToken(int expiresInMinutes, params (object Key, object Value)[] claims)
        {
            return CreateAccessToken(claims.ToLookup(x => x.Key, x => x.Value), expiresInMinutes);
        }

        /// <summary>
        /// Creates the token async.
        /// </summary>
        /// <returns>The token async.</returns>
        /// <param name="claims">Claims.</param>
        public Task<AccessTokenModel> CreateAccessTokenAsync(int expiresInMinutes,
            params (object Key, object Value)[] claims) =>
            Task.Run(() => CreateAccessToken(expiresInMinutes, claims));

        /// <summary>
        /// Creates the token async.
        /// </summary>
        /// <returns>The token async.</returns>
        /// <param name="claimsLookUp">Look up.</param>
        public Task<AccessTokenModel>
            CreateAccessTokenAsync(ILookup<object, object> claimsLookUp, int expiresInMinutes) =>
            Task.Run(() => CreateAccessToken(claimsLookUp, expiresInMinutes));

        /// <summary>
        /// Creates the token.
        /// </summary>
        /// <returns>The token.</returns>
        /// <param name="keyValues">Key values.</param>
        public AccessTokenModel CreateAccessToken(IEnumerable<KeyValuePair<object, object>> keyValues,
            int expiresInMinutes) =>
            CreateAccessToken(keyValues.ToLookup(x => x.Key, x => x.Value), expiresInMinutes);

        /// <summary>
        /// Creates the token.
        /// </summary>
        /// <returns>The token.</returns>
        /// <param name="claimsLookUp">Claims look up.</param>
        public AccessTokenModel CreateAccessToken(ILookup<object, object> claimsLookUp, int expiresInMinutes)
        {
            var now = DateTime.UtcNow;
            var expires = now.AddMinutes(expiresInMinutes);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _tokenInfo.Issuer,
                audience: _tokenInfo.Audience,
                notBefore: now,
                claims: claimsLookUp.Any()
                    ? claimsLookUp.Select(x => new Claim(x.Key.ToString(), x.FirstOrDefault()?.ToString()))
                    : null,
                expires: expires,
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_tokenInfo.IssuerSecurityKey)),
                    SecurityAlgorithms.HmacSha256));

            return new AccessTokenModel
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                ExpireAt = expires
            };
        }

        public TokenExternalLoginInfo GetTokenExternalLoginInfo(string token)
        {
            TokenExternalLoginInfo tokenExternalLoginInfo = null;

            if (!IsTokenValid(token))
            {
                return null;
            }

            IEnumerable<Claim> claims = GetClaims(token);
            Claim emailClaim = claims.FirstOrDefault(x => x.Type == ClaimTypes.Email);
            Claim nameIdentifier = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);

            if (emailClaim == null)
            {
                return null;
            }

            if (nameIdentifier == null)
            {
                return null;
            }

            tokenExternalLoginInfo = new TokenExternalLoginInfo
            {
                Email = emailClaim.Value,
                UserId = nameIdentifier.Value
            };

            return tokenExternalLoginInfo;
        }


        /// <summary>
        /// Gets the claims.
        /// </summary>
        /// <returns>The claims.</returns>
        /// <param name="token">Token.</param>
        public IEnumerable<Claim> GetClaims(string token)
        {
            if (!IsTokenValid(token))
                throw new Exception("Token is invalid");

            var handler = new JwtSecurityTokenHandler();

            var jwtSecurityToken = handler.ReadToken(token.Replace("Bearer ", string.Empty)) as JwtSecurityToken;
            if (jwtSecurityToken == null)
                return Enumerable.Empty<Claim>();

            return jwtSecurityToken.Claims;
        }

        /// <summary>
        /// Ises the token valid.
        /// </summary>
        /// <returns><c>true</c>, if token valid was ised, <c>false</c> otherwise.</returns>
        /// <param name="token">Token.</param>
        public bool IsTokenValid(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            bool isValid = false;

            SecurityToken securityKey = null;
            try
            {
                handler.ValidateToken(token, new TokenValidationParameters()
                {
                    ValidateIssuer = _tokenInfo.ValidateIssuer,
                    ValidateLifetime = _tokenInfo.ValidateLifetime,
                    ValidateIssuerSigningKey = _tokenInfo.ValidateIssuerSigningKey,
                    ValidateAudience = _tokenInfo.ValidateAudience,

                    ValidIssuer = _tokenInfo.Issuer,
                    ValidAudience = _tokenInfo.Audience,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_tokenInfo.IssuerSecurityKey))
                }, out securityKey);

                isValid = (securityKey != null);
            }
            catch
            {
                isValid = false;
            }

            return isValid;
        }
    }
}
