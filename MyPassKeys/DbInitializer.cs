using Microsoft.EntityFrameworkCore;

namespace MyPassKeys;

public static class DbInitializer
{
    public static void EnsureDatabase(IApplicationBuilder app)
    {
        using var scope = app.ApplicationServices.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        
        // Creates the database schema if it doesn't exist
        context.Database.EnsureCreated();
    }
}