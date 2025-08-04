using System;
using System.Security.Cryptography;
using System.Text;
using MySql.Data.MySqlClient;

/// <summary>
/// Refer to the project GDD for overall authentication plan.
/// Simple login utility for Unity that connects to a local MySQL server.
/// Uses salted SHA256 hashes and parameterized queries to avoid SQL injection.
/// </summary>
public class LoginManager
{
    private const string ConnectionString = "Server=localhost;Port=3306;Database=autoB;Uid=root;Pwd=;";

    /// <summary>
    /// Attempts to log the user in by verifying the supplied password against the stored hash.
    /// </summary>
    public bool TryLogin(string username, string password)
    {
        using (var connection = new MySqlConnection(ConnectionString))
        {
            connection.Open();
            var cmd = new MySqlCommand("SELECT password_hash, salt FROM accounts WHERE username = @username", connection);
            cmd.Parameters.AddWithValue("@username", username);

            using (var reader = cmd.ExecuteReader())
            {
                if (!reader.Read())
                    return false; // user not found

                string storedHash = reader.GetString("password_hash");
                string salt = reader.GetString("salt");
                string computedHash = ComputeHash(password, salt);
                return StringComparer.Ordinal.Compare(storedHash, computedHash) == 0;
            }
        }
    }

    /// <summary>
    /// Registers a new account with a salted hash. Returns false if the username already exists.
    /// </summary>
    public bool Register(string username, string password)
    {
        string salt = GenerateSalt();
        string hash = ComputeHash(password, salt);

        using (var connection = new MySqlConnection(ConnectionString))
        {
            connection.Open();
            var cmd = new MySqlCommand("INSERT INTO accounts (username, password_hash, salt) VALUES (@username, @hash, @salt)", connection);
            cmd.Parameters.AddWithValue("@username", username);
            cmd.Parameters.AddWithValue("@hash", hash);
            cmd.Parameters.AddWithValue("@salt", salt);

            try
            {
                cmd.ExecuteNonQuery();
                return true;
            }
            catch (MySqlException)
            {
                // Likely username already exists
                return false;
            }
        }
    }

    private static string ComputeHash(string password, string salt)
    {
        using (var sha = SHA256.Create())
        {
            byte[] bytes = Encoding.UTF8.GetBytes(password + salt);
            byte[] hash = sha.ComputeHash(bytes);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }
    }

    private static string GenerateSalt()
    {
        byte[] salt = new byte[8]; // 16 hex characters
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }
        return BitConverter.ToString(salt).Replace("-", "").ToLowerInvariant();
    }
}
