using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using Common.Options;
using Common.Providers.Contract;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using VoiceAssistants.Authorization.Data.Requests;

namespace VoiceAssistants.Authorization.Controllers
{
    [Route("[controller]")]
    public class ManageController : Controller
    {
        private readonly ITokenProvider _tokenProvider;
        private readonly IOptions<JwtTokenOptions> _jwtTokenOptions;

        public ManageController(
          ITokenProvider tokenProvider,
         IOptions<JwtTokenOptions> jwtTokenOptions)
        {
            _tokenProvider = tokenProvider;
            _jwtTokenOptions = jwtTokenOptions;
        }

        [HttpPost("ExternalLogin")]
        public async Task<ActionResult> ExternalLoginAsync([FromForm] ExternalLoginRequest model)
        {
            // describe real logic  here
            //var user = await _userManager.FindByEmailAsync(model.Email);
            var user = new
            {
                Id = Guid.NewGuid(),
                LastName = "Less",
                FirstName = "Steve",
                EmailConfirmed = true,
            };

            if (user == null)
            {
                return BadRequest("User not found.!");
            }

            if (!user.EmailConfirmed)
            {
                return BadRequest("User should confirm his email.");
            }

            // describe real logic  here
            //var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, lockoutOnFailure: true);
            var result = new
            {
                Succeeded = true,
            };

            if (result.Succeeded)
            {
                List<KeyValuePair<object, object>> keyValueList = new List<KeyValuePair<object, object>>
                {
                    new KeyValuePair<object, object>(ClaimTypes.Email, model.Email),
                    new KeyValuePair<object, object>(ClaimTypes.NameIdentifier, user.Id),
                };

                var accessToken = _tokenProvider.CreateAccessToken(keyValueList, _jwtTokenOptions.Value.LifetimeExternal);

                var redirectUrl = model.RedirectUri + "#state=" + HttpUtility.UrlEncode(model.State) +
                                  "&access_token=" +
                                  HttpUtility.UrlEncode(accessToken.AccessToken) + "&token_type=Bearer";

                return new RedirectResult(redirectUrl);
            }

            return BadRequest();
        }

        [HttpGet("ExternalLogin")]
        public IActionResult ExternalLoginCallback(string state, string client_id, string scope, string response_type, string redirect_uri)
        {
            return View("ExternalLogin", new ExternalLoginRequest
            {
                State = state,
                ClientID = client_id,
                Scope = scope,
                RedirectUri = redirect_uri,
                ResponseType = response_type,
            });
        }
    }
}
