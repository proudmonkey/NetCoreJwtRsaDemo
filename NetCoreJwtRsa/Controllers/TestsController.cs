using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using static Microsoft.AspNetCore.Http.StatusCodes;

namespace NetCoreJwtRsa.Controllers
{
    [Route("api/v1/[controller]")]
    public class TestsController : ControllerBase
    {
        private readonly IJwtHandler _jwtHandler;
        public TestsController(IJwtHandler jwtHandler)
        {
            _jwtHandler = jwtHandler;
        }

        [HttpPost]
        [Route("token")]
        [ProducesResponseType(typeof(string), Status200OK)]
        public IActionResult GenerateJwt()
        {

            var claims = new JwtCustomClaims
            {
                FirstName = "Vynn",
                LastName = "Durano",
                Email = "whatever@email.com"
            };

            var jwt = _jwtHandler.CreateToken(claims);

            var link = _jwtHandler.GenerateLink(jwt.Token);

            return Ok(jwt);
        }

        [HttpPost]
        [Route("token/validate")]
        [ProducesResponseType(typeof(string), Status200OK)]
        public IActionResult ValidateJwt([FromBody] string token)
        {

            if (_jwtHandler.ValidateToken(token))
            {
                var handler = new JwtSecurityTokenHandler();
                var jwtToken = handler.ReadToken(token) as JwtSecurityToken;

                var claims = new JwtCustomClaims
                {
                    FirstName = jwtToken.Claims.First(claim => claim.Type == "FirstName").Value,
                    LastName = jwtToken.Claims.First(claim => claim.Type == "LastName").Value,
                    Email = jwtToken.Claims.First(claim => claim.Type == "Email").Value
                };

                return Ok(claims);
            }

            return BadRequest("Token is invalid.");
        }
    }
}