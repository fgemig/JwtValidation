using JwtValidation.Models;
using JwtValidation.Models.Commands;
using JwtValidation.Security;
using JwtValidation.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

namespace JwtValidation.Controllers
{
    public class LoginController : Controller
    {
        private readonly JwtTokenOptions _tokenOptions;
        private Usuario _usuario;

        public LoginController(IOptions<JwtTokenOptions> jwtOptions)
        {
            _tokenOptions = jwtOptions.Value;
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("v1/autenticar")]
        public async Task<IActionResult> Post([FromForm] AutenticarCommand command)
        {
            if (command == null)
                return BadRequest("Usuário ou Senha inválidos.");

            var identity = await ObterClaims(command);

            if (identity == null)
                return BadRequest("Usuário ou Senha inválidos.");

            var userClaims = new[]
            {
                new Claim(JwtRegisteredClaimNames.UniqueName, _usuario.Nome.ToString()),
                new Claim(JwtRegisteredClaimNames.Sub, _usuario.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, await _tokenOptions.JtiGenerator()),
                new Claim(JwtRegisteredClaimNames.Iat, _tokenOptions.ToUnixEpochDate().ToString(), ClaimValueTypes.Integer64),
                identity.FindFirst("JwtValidation")
            };

            var jwt = new JwtSecurityToken(
                issuer: _tokenOptions.Issuer,
                audience: _tokenOptions.Audience,
                claims : userClaims,
                notBefore: _tokenOptions.NotBefore,
                expires: _tokenOptions.Expiration,
                signingCredentials: _tokenOptions.SigningCredentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            var response = new
            {
                token = encodedJwt,
                expires = _tokenOptions.Expiration,
                usuario = new
                {
                    id = _usuario.Id,
                    nome = _usuario.Nome
                }
            };

            return new OkObjectResult(
                JsonConvert.SerializeObject(response));
        }

        private Task<ClaimsIdentity> ObterClaims(AutenticarCommand command)
        {
            var usuarioService = new UsuarioService();

            var usuario = usuarioService.Autenticar(command.Usuario, command.Senha);

            if (usuario == null)
                return Task.FromResult<ClaimsIdentity>(null);

            _usuario = usuario;

            return Task.FromResult(new ClaimsIdentity(
                new GenericIdentity(_usuario.Nome, "Token"),
                new[] {
                    new Claim("JwtValidation", "Usuario")
                }));
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("v1/token/validar")]
        public bool ValidarToken([FromBody]string token)
        {
            var validationParameters = new TokenValidationParameters()
            {
                ValidIssuer = _tokenOptions.Issuer,
                ValidAudience = _tokenOptions.Audience,
                IssuerSigningKey = _tokenOptions.SigningKey,
                RequireExpirationTime = true
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken = null;

            try
            {
                tokenHandler.ValidateToken(token, validationParameters, out securityToken);
            }
            catch
            {
                return false;
            }

            return securityToken != null;
        }

    }
}
