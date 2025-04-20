using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

public class DatabaseHandlerEfCoreExample : IdentityDbContext<IdentityUser>
{
    public DatabaseHandlerEfCoreExample(DbContextOptions<DatabaseHandlerEfCoreExample> options)
        : base(options)
    {
    }
}