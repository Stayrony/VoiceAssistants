using System;
using System.ComponentModel.DataAnnotations;

namespace VoiceAssistants.Authorization.Data.Requests
{
    public class ExternalLoginRequest
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

        /// <summary>
        /// A value used internally by the service to track the user through the account linking process.
        /// </summary>
        public string State { get; set; }

        /// <summary>
        /// A unique string that identifies the client requesting authentication. 
        /// </summary>
        public string ClientID { get; set; }

        /// <summary>
        /// An optional list of permissions for the other service.
        /// </summary>
        public string Scope { get; set; }

        /// <summary>
        /// Indicates the type of response that should be returned after
        /// the user has been authenticated by the other service.
        /// This is always token for implicit grant.
        /// </summary>
        public string ResponseType { get; set; }

        /// <summary>
        /// The redirection endpoint (redirect URL) to which the service should
        /// redirect the user after authenticating the user. 
        /// </summary>
        public string RedirectUri { get; set; }
    }
}
