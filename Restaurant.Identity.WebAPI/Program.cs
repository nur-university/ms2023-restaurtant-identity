using Microsoft.Extensions.Hosting;
using Restaurant.Identity.Infrastructure;
using Restaurant.Identity.Infrastructure.Config;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddInfrastructure(builder.Configuration);


builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    IWebHostEnvironment env = scope.ServiceProvider.GetRequiredService<IWebHostEnvironment>();
    SecurityInitializer securityInitializer = scope.ServiceProvider.GetRequiredService<SecurityInitializer>();
    

    string contentRootPath = env.ContentRootPath;
    var permissionJsonFilePath = contentRootPath + "/DataFiles/permissions.json";
    var securityInitializationJsonFilePath = contentRootPath + "/DataFiles/initializer.json";

    await securityInitializer.Initialize(permissionJsonFilePath, securityInitializationJsonFilePath);

}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
