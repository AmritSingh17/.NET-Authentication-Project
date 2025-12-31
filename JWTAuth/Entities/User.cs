namespace JWTAuth.Entities
{
    public class User
    {
        public Guid Id { get; set; }
        public string userName { get; set; } = string.Empty;
        public string passwordHash { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
    }
}
