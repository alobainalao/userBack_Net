using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MyJwtApi.DTOs;
using MyJwtApi.Servicios;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace MyJwtApi.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly HashService _hashService;
        private readonly IDataProtector _dataProtector;
        private readonly IEmailSender _emailSender;

        public AuthController(
            UserManager<IdentityUser> userManager,
            IConfiguration configuration,
            SignInManager<IdentityUser> signInManager,
            IDataProtectionProvider dataProtectionProvider,
            HashService hashService,
            IEmailSender emailSender)
        {
            _userManager = userManager;
            _configuration = configuration;
            _signInManager = signInManager;
            _hashService = hashService;
            _dataProtector = dataProtectionProvider.CreateProtector("valor_unico_y_quizas_secreto");
            _emailSender = emailSender;
        }

        [HttpGet("hash/{textoPlano}")]
        public ActionResult RealizarHash(string textoPlano)
        {
            if (string.IsNullOrWhiteSpace(textoPlano))
                return BadRequest("El texto plano no puede ser vacío.");

            return Ok(new
            {
                textoPlano,
                Hash1 = _hashService.Hash(textoPlano),
                Hash2 = _hashService.Hash(textoPlano)
            });
        }

        [HttpGet("encriptar")]
        public ActionResult Encriptar()
        {
            var textoPlano = "Alex";
            var textoCifrado = _dataProtector.Protect(textoPlano);
            var textoDesencriptado = _dataProtector.Unprotect(textoCifrado);

            return Ok(new { textoPlano, textoCifrado, textoDesencriptado });
        }

        [HttpGet("encriptarPorTiempo")]
        public async Task<ActionResult> EncriptarPorTiempo()
        {
            var protectorTiempo = _dataProtector.ToTimeLimitedDataProtector();
            var textoPlano = "Alex";
            var textoCifrado = protectorTiempo.Protect(textoPlano, TimeSpan.FromSeconds(5));

            await Task.Delay(6000);

            string textoDesencriptado;
            try
            {
                textoDesencriptado = protectorTiempo.Unprotect(textoCifrado);
            }
            catch
            {
                textoDesencriptado = "El texto cifrado ha expirado o es inválido.";
            }

            return Ok(new { textoPlano, textoCifrado, textoDesencriptado });
        }

        [AllowAnonymous]
        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrWhiteSpace(token))
                return BadRequest("Parámetros inválidos.");

            var usuario = await _userManager.FindByIdAsync(userId);
            if (usuario == null)
                return NotFound("Usuario no encontrado.");

            var resultado = await _userManager.ConfirmEmailAsync(usuario, token);

            return resultado.Succeeded
                ? Ok("Correo confirmado exitosamente. Ya puedes iniciar sesión.")
                : BadRequest($"Error al confirmar el correo: {string.Join(", ", resultado.Errors.Select(e => e.Description))}");
        }

        [AllowAnonymous]
        [HttpPost("registrar")]
        public async Task<ActionResult> Registrar(RegisterCredentialDTO dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var usuario = await _userManager.FindByEmailAsync(dto.Email);

            if (usuario != null)
            {
                if (usuario.EmailConfirmed)
                    return BadRequest("Ya existe un usuario con este email.");

                await EnviarCorreoConfirmacionAsync(usuario);
                return Ok(new { Mensaje = "Se ha reenviado el enlace de confirmación." });
            }

            usuario = new IdentityUser { UserName = dto.Email, Email = dto.Email };
            var resultado = await _userManager.CreateAsync(usuario, dto.Password);

            if (!resultado.Succeeded)
                return BadRequest(resultado.Errors.Select(e => e.Description));

            await EnviarCorreoConfirmacionAsync(usuario);
            return Ok(new { Mensaje = "Registro exitoso. Revisa tu correo para confirmar la cuenta." });
        }

        [AllowAnonymous]
        [HttpPost("resend-confirmation")]
        public async Task<IActionResult> ResendConfirmation([FromQuery] string email)
        {
            var usuario = await ObtenerUsuarioPorEmailAsync(email);
            if (usuario == null) return NotFound(new { message = "Usuario no encontrado." });
            if (usuario.EmailConfirmed) return BadRequest(new { message = "El correo ya está confirmado." });

            await EnviarCorreoConfirmacionAsync(usuario);
            return Ok(new { message = "Correo reenviado con éxito." });
        }

        [AllowAnonymous]
        [HttpGet("is-confirmed")]
        public async Task<IActionResult> IsConfirmed(string email)
        {
            var user = await ObtenerUsuarioPorEmailAsync(email);
            return user == null
                ? NotFound()
                : Ok(new { confirmed = user.EmailConfirmed });
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<ActionResult<RespuestaAutenticacion>> Login(CredencialesUsuario dto)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);

            var usuario = await _userManager.FindByEmailAsync(dto.Email);
            if (usuario == null || !await _userManager.IsEmailConfirmedAsync(usuario))
                return Unauthorized("Debe confirmar su correo electrónico.");

            var resultado = await _signInManager.PasswordSignInAsync(dto.Email, dto.Password, false, true);

            return resultado.Succeeded
                ? await ConstruirToken(dto)
                : Unauthorized(resultado.IsLockedOut ? "Cuenta bloqueada temporalmente." : "Credenciales inválidas.");
        }

        [HttpGet("Renovar")]
        public async Task<ActionResult<RespuestaAutenticacion>> Renovar()
        {
            var email = User.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
            if (email == null) return Unauthorized("No se encontró el claim de email.");

            var usuario = await _userManager.FindByEmailAsync(email);
            if (usuario == null) return Unauthorized("Usuario no encontrado.");

            return await ConstruirToken(new CredencialesUsuario { Email = email });
        }

        [HttpPost("HacerAdmin")]
        public async Task<ActionResult> HacerAdmin(EditarAdminDTO dto)
        {
            var usuario = await ObtenerUsuarioPorEmailAsync(dto.Email);
            if (usuario == null) return NotFound("Usuario no encontrado.");

            var resultado = await _userManager.AddClaimAsync(usuario, new Claim("esAdmin", "1"));
            return resultado.Succeeded ? NoContent() : BadRequest(resultado.Errors.Select(e => e.Description));
        }

        [HttpPost("RemoverAdmin")]
        public async Task<ActionResult> RemoverAdmin(EditarAdminDTO dto)
        {
            var usuario = await ObtenerUsuarioPorEmailAsync(dto.Email);
            if (usuario == null) return NotFound("Usuario no encontrado.");

            var resultado = await _userManager.RemoveClaimAsync(usuario, new Claim("esAdmin", "1"));
            return resultado.Succeeded ? NoContent() : BadRequest(resultado.Errors.Select(e => e.Description));
        }

        // ────────────────────────────────
        // MÉTODOS PRIVADOS REUTILIZABLES
        // ────────────────────────────────

        private async Task<IdentityUser?> ObtenerUsuarioPorEmailAsync(string email)
            => await _userManager.FindByEmailAsync(email);

        private async Task<string> GenerarLinkConfirmacionAsync(IdentityUser usuario)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(usuario);
            return Url.Action(nameof(ConfirmEmail), "Auth", new { userId = usuario.Id, token }, Request.Scheme)!;
        }

        private async Task EnviarCorreoConfirmacionAsync(IdentityUser usuario)
        {
            var link = await GenerarLinkConfirmacionAsync(usuario);
            await _emailSender.SendEmailAsync(usuario.Email, "Confirma tu cuenta",
                $"Por favor confirma tu cuenta haciendo clic <a href='{link}'>aquí</a>");
        }

        private async Task<RespuestaAutenticacion> ConstruirToken(CredencialesUsuario dto)
        {
            var usuario = await _userManager.FindByEmailAsync(dto.Email);
            if (usuario == null) throw new ArgumentException("Usuario no encontrado.");

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, usuario.Id),
                new Claim("email", dto.Email),
                new Claim("user", dto.Email.Split('@')[0])
            };

            claims.AddRange(await _userManager.GetClaimsAsync(usuario));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
                _configuration["llavejwt"] ?? throw new InvalidOperationException("JWT key not set.")));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expiracion = DateTime.UtcNow.AddHours(1);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: expiracion,
                signingCredentials: creds);

            return new RespuestaAutenticacion
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiracion = expiracion
            };
        }
    }
}
