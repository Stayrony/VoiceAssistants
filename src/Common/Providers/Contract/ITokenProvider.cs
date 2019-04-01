using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Common.Models;

namespace Common.Providers.Contract
{
    public interface ITokenProvider
    {
        AccessTokenModel CreateAccessToken(int expiresInMinutes, params (object Key, object Value)[] claims);
        AccessTokenModel CreateAccessToken(ILookup<object, object> lookUp, int expiresInMinutes);
        AccessTokenModel CreateAccessToken(IEnumerable<KeyValuePair<object, object>> keyValues, int expiresInMinutes);
        Task<AccessTokenModel> CreateAccessTokenAsync(ILookup<object, object> lookUp, int expiresInMinutes);
        Task<AccessTokenModel> CreateAccessTokenAsync(int expiresInMinutes, params (object Key, object Value)[] claims);
        TokenExternalLoginInfo GetTokenExternalLoginInfo(string token);
        bool IsTokenValid(string token);
        IEnumerable<Claim> GetClaims(string token);

        TokenInfo TokenInfo { get; }
    }
}
