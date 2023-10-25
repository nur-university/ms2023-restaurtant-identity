
using Restaurant.Identity.Application.Dto;

namespace Restaurant.Identity.Application.Services;

public interface ISecurityService
{
    Task<Result<string>> Login(string username, string password);

    Task<Result> Register(RegisterAplicationUserModel model, bool isAdmin, bool emailConfirmationRequired);
}
