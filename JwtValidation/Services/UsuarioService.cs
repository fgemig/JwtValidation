using JwtValidation.Models;

namespace JwtValidation.Services
{
    public class UsuarioService
    {
        public Usuario Autenticar(string usuario, string senha)
        {
            // Não faça isso! :)
            if (usuario == "Bruce" && senha == "powerslave")
                return Usuario.NovoUsuario();

            return null;
        }
    }
}
