namespace JWTAuth.Models
{
    public class UserRegisterDto
    {
        public Guid Id { get; set; }
        public string UserName { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
    }
}
