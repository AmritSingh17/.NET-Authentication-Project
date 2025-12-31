using JWTAuth.Entities;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth.Data
{
    public class UserDBContext(DbContextOptions<UserDBContext> options) : DbContext(options)
    {
        public DbSet<User> Users {  get; set; }
    }
}
