﻿namespace Restaurant.Identity.Application.Dto;

public class RegisterAplicationUserModel
{
    public string Username { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Password { get; set; }
    public string Email { get; set; }

    public List<string> Roles { get; set; }

    public RegisterAplicationUserModel()
    {
        Username = "";
        FirstName = "";
        LastName = "";
        Password = "";
        Email = "";
        Roles = new List<string>();

    }
}
