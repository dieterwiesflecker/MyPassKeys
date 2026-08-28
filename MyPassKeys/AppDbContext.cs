using Microsoft.EntityFrameworkCore;

namespace MyPassKeys;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<Fido2AppUser> Users { get; set; }
    public DbSet<Fido2StoredCredential> Credentials { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Fido2AppUser>(b =>
        {
            b.HasKey(u => u.Id);
            b.HasIndex(u => u.Username).IsUnique();
        });

        modelBuilder.Entity<Fido2StoredCredential>(b =>
        {
            b.HasKey(c => c.Id);
            b.HasIndex(c => c.UserId);
        });
    }
}
