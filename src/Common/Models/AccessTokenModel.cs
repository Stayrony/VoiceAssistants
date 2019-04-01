using System;
namespace Common.Models
{
    public class AccessTokenModel
    {
        public string AccessToken { get; set; }
        public DateTime ExpireAt { get; set; }
    }
}
