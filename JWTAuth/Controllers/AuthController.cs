using JWTAuth.Entities;
using JWTAuth.Models;
using JWTAuth.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JWTAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController(IAuthService authService) : ControllerBase
    {
        [HttpPost("register")]
        //{base_url}/api/Auth/register
        public async Task<ActionResult<UserRegisterDto>> Register(UserDto request)
        {
           var user = await authService.RegisterAsync(request);
            if (user == null)
            {
                return BadRequest("User Already Exist");
            }
            var response = new UserRegisterDto
            {
                Id = user.Id,
                UserName = user.userName,
                Role = user.Role
            };
            return Ok(response);
        }

        [HttpPost("login")]
        public async Task<ActionResult<User>> Login(UserDto request)
        {
            var response = await authService.LoginAsync(request);
            if(response == null)
            {
                return BadRequest("Invalid Username or Password");
            }
            return Ok(response);
        }

        [HttpPost("refresh-token")]
        public async Task<ActionResult<TokenResponseDto>> RefreshTokenValidation(RefreshTokenRequestDto refreshTokenRequest)
        {
            var result = await authService.RefreshTokensAsync(refreshTokenRequest);
            if(result == null || result.AccessToken == null|| result.RefreshToken == null)
            {
                return BadRequest("Invalid Refresh Token");
            }
            return Ok(result);
        }

        [Authorize]
        [HttpGet("getOrders")]
        public ActionResult GetOrders()
        {
            return Ok("Authorized user");
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("getProducts")]
        public ActionResult GetProducts()
        {
            return Ok("You are an admin");
        }




    }
}
