using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;
using System.Threading.Tasks;

namespace JwtValidation.Security
{
    public class JwtTokenOptions
    {
        public SymmetricSecurityKey SigningKey = 
            new SymmetricSecurityKey(Encoding.ASCII.GetBytes("c1f51f42-5727-4d15-b787-c6bbbb645024"));

        public string Issuer { get; set; } = "Issuer";

        public string Audience { get; set; } = "Audience";
        
        public DateTime NotBefore => DateTime.Now;

        public DateTime IssuedAt => DateTime.Now;
        
        public DateTime Expiration => DateTime.Now.AddMinutes(1);

        public SigningCredentials SigningCredentials { get; set; }
     
        public Func<Task<string>> JtiGenerator =>
          () => Task.FromResult(Guid.NewGuid().ToString());

        public long ToUnixEpochDate()
          => (long)Math.Round((IssuedAt.ToUniversalTime() - 
              new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }

}
