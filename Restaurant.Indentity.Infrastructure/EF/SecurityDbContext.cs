﻿using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Restaurant.Identity.Infrastructure.PersistenceModel;

namespace Restaurant.Identity.Infrastructure.EF
{
    public class SecurityDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>
    {

        public SecurityDbContext(
           DbContextOptions<SecurityDbContext> options) : base(options)
        {

        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            // We call this so all the keys for identity are called
            // To create the Identity tables we need to type in the package manager console:
            //
            // Add-Migration v_1_0_0_Identity
            // update-database 
            base.OnModelCreating(builder);

            builder.Entity<ApplicationUser>(b =>
            {
                b.Property(u => u.Id).HasDefaultValueSql("newsequentialid()");
            });

            builder.Entity<ApplicationRole>(b =>
            {
                b.Property(u => u.Id).HasDefaultValueSql("newsequentialid()");
            });


        }
    }
}
