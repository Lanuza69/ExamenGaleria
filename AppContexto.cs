using System;
using System.IO;
using System.Data.SQLite;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Newtonsoft.Json;

namespace Galeria
{


    public class AppContexto : ApplicationContext
    {
        //readonly porque las rutas no cambian durante la ejecución, pero se asignan en el contructor porque dependen de la ruta de inicio
        private readonly string rutaData;
        private readonly string rutaBD;
        private readonly string rutaJSON;
        private readonly string rutaKey;

        private  static byte[] AES_KEY; //static porque EncriptarAES y DesencriptarAES son métodos estáticos para poder usarlos en cualquier clase

        private const string ADMIN_PSW = "AlejandroDameUn10"; 

        public AppContexto()
        {
            rutaData = Path.Combine(Application.StartupPath, "data");
            rutaBD = Path.Combine(rutaData, "GaleriaArte.sqlite");
            rutaJSON = Path.Combine(rutaData, "sesion.json");
            rutaKey = Path.Combine(rutaData, "key.bin");
            MostrarSplash();
        }

        /// <summary>
        /// Formulario pensando para cargar el sistema mientras se muestra una pantalla de carga
        /// </summary>
        private async void MostrarSplash()
        {
            var splash = new FormSplash();
            splash.Show();

            await Task.Run(() => InicializarSistema());

            splash.Close();

            var sesion = LeerSesionJSON();

            if (sesion == null || !ValidarSesionSQLite(sesion))
            {
                MostrarLogin();
            }
            else
            {
                MostrarPrincipal(sesion);
            }
        }

        // ---------------------------------------------------------
        // INICIALIZACIÓN DEL SISTEMA
        // ---------------------------------------------------------
        private void InicializarSistema()
        {
            if (!Directory.Exists(rutaData))
                Directory.CreateDirectory(rutaData);

            bool keyExistiaAntes = File.Exists(rutaKey);
            bool bdExistiaAntes = File.Exists(rutaBD);

            CargarClaveAES();

            if (!bdExistiaAntes)
                CrearBaseDeDatos();

            if (!keyExistiaAntes && File.Exists(rutaJSON))
                File.Delete(rutaJSON);

            CrearOActualizarUsuarioAdmin();
        }


        private void CargarClaveAES()
        {
            if (File.Exists(rutaKey))
            {
                byte[] protegido = File.ReadAllBytes(rutaKey);
                AES_KEY = ProtectedData.Unprotect(protegido, null, DataProtectionScope.CurrentUser);//Optiene la clava AES encriptada y la desencripta para usarla en el sistema
            }
            else { 

            AES_KEY = GenerarClaveAES32();

            byte[] protegidoNuevo = ProtectedData.Protect(AES_KEY, null, DataProtectionScope.CurrentUser);//Encripta la propia clave AES para guardarla de forma segura en el sistema
                File.WriteAllBytes(rutaKey, protegidoNuevo);
            File.SetAttributes(rutaKey, FileAttributes.Hidden | FileAttributes.ReadOnly);//Oculta el archivo y lo marca como solo lectura para mayor seguridad
            }
        }

        private byte[] GenerarClaveAES32()
        {
            byte[] key = new byte[32];
            using (var rdm = RandomNumberGenerator.Create()) //Genera la clave AES utilizando un generador de bytes aleatorios gracias a cryptography, var porque no se que valor devuelve  exactamente el método 
                rdm.GetBytes(key);
            return key;
        }

        // ---------------------------------------------------------
        // AES ENCRIPTAR / DESENCRIPTAR
        // ---------------------------------------------------------
        public static string EncriptarAES(string texto)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = AES_KEY;
                aes.GenerateIV();

                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] datos = Encoding.UTF8.GetBytes(texto);
                    byte[] cifrado = encryptor.TransformFinalBlock(datos, 0, datos.Length);

                    byte[] resultado = new byte[aes.IV.Length + cifrado.Length];
                    Buffer.BlockCopy(aes.IV, 0, resultado, 0, aes.IV.Length);
                    Buffer.BlockCopy(cifrado, 0, resultado, aes.IV.Length, cifrado.Length);

                    return Convert.ToBase64String(resultado);
                }
            }
        }

        public static string DesencriptarAES(string base64)
        {
            byte[] datos = Convert.FromBase64String(base64);

            using (Aes aes = Aes.Create())
            {
                aes.Key = AES_KEY;

                byte[] iv = new byte[16];
                byte[] cifrado = new byte[datos.Length - 16];

                Buffer.BlockCopy(datos, 0, iv, 0, 16);
                Buffer.BlockCopy(datos, 16, cifrado, 0, cifrado.Length);

                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor())
                {
                    byte[] plano = decryptor.TransformFinalBlock(cifrado, 0, cifrado.Length);
                    return Encoding.UTF8.GetString(plano);
                }
            }
        }

        // ---------------------------------------------------------
        // CREAR BASE DE DATOS
        // ---------------------------------------------------------
        private void CrearBaseDeDatos()
        {
            SQLiteConnection.CreateFile(rutaBD);

            using (var con = new SQLiteConnection("Data Source=" + rutaBD))
            {
                con.Open();

                string sql = @"
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS Usuario (
                IdUsuario INTEGER PRIMARY KEY AUTOINCREMENT,
                Nombre TEXT NOT NULL,
                Contrasena TEXT NOT NULL,
                Control CHAR(1) NOT NULL
            );
            ";

                new SQLiteCommand(sql, con).ExecuteNonQuery();
            }
        }

        // ---------------------------------------------------------
        // CREAR O ACTUALIZAR USUARIO ADMIN
        // ---------------------------------------------------------
        private void CrearOActualizarUsuarioAdmin()
        {
            using (var con = new SQLiteConnection("Data Source=" + rutaBD))
            {
                con.Open();

                string sqlCount = "SELECT COUNT(*) FROM Usuario WHERE IdUsuario = 0";
                long count = (long)new SQLiteCommand(sqlCount, con).ExecuteScalar();

                string passCifrada = EncriptarAES(ADMIN_PSW);

                if (count == 0)
                {
                    string insert = @"INSERT INTO Usuario (IdUsuario, Nombre, Contrasena, Control)
                                  VALUES (0, 'Admin', @pass, 'A')";

                    var cmd = new SQLiteCommand(insert, con);
                    cmd.Parameters.AddWithValue("@pass", passCifrada);
                    cmd.ExecuteNonQuery();
                }
                else
                {
                    string update = @"UPDATE Usuario 
                                  SET Contrasena = @pass, Nombre = 'Admin', Control = 'A'
                                  WHERE IdUsuario = 0";

                    var cmd = new SQLiteCommand(update, con);
                    cmd.Parameters.AddWithValue("@pass", passCifrada);
                    cmd.ExecuteNonQuery();
                }
            }
        }

        // ---------------------------------------------------------
        // JSON SESIÓN
        // ---------------------------------------------------------
        private SesionUsuario LeerSesionJSON()
        {
            if (!File.Exists(rutaJSON))
                return null;

            try
            {
                string json = File.ReadAllText(rutaJSON);
                return JsonConvert.DeserializeObject<SesionUsuario>(json);
            }
            catch
            {
                return null;
            }
        }

        private void GuardarSesionJSON(SesionUsuario sesion)
        {
            string json = JsonConvert.SerializeObject(sesion, Formatting.Indented);
            File.WriteAllText(rutaJSON, json);
        }

        private void BorrarSesionJSON()
        {
            if (File.Exists(rutaJSON))
                File.Delete(rutaJSON);
        }

        // ---------------------------------------------------------
        // VALIDAR SESIÓN CONTRA SQLITE
        // ---------------------------------------------------------
        private bool ValidarSesionSQLite(SesionUsuario sesion)
        {
            using (var con = new SQLiteConnection("Data Source=" + rutaBD))
            {
                con.Open();

                string sql = "SELECT Contrasena FROM Usuario WHERE Nombre = @u";
                var cmd = new SQLiteCommand(sql, con);
                cmd.Parameters.AddWithValue("@u", sesion.Usuario);

                var result = cmd.ExecuteScalar();
                if (result == null) return false;

                string passBD = result.ToString();
                string passJSON = EncriptarAES(sesion.Contrasena);

                return passBD == passJSON;
            }
        }

        private string ObtenerControlUsuario(string usuario)
        {
            using (var con = new SQLiteConnection("Data Source=" + rutaBD))
            {
                con.Open();

                string sql = "SELECT Control FROM Usuario WHERE Nombre = @u";
                var cmd = new SQLiteCommand(sql, con);
                cmd.Parameters.AddWithValue("@u", usuario);

                return cmd.ExecuteScalar()?.ToString() ?? "U";
            }
        }

        // ---------------------------------------------------------
        // LOGIN Y PRINCIPAL
        // ---------------------------------------------------------
        private void MostrarLogin()
        {
            var login = new FormLogin();

            login.OnLoginCorrecto += (usuario, contrasena, darkMode, control) =>
            {
                var sesion = new SesionUsuario
                {
                    Usuario = usuario,
                    Contrasena = contrasena,
                    DarkMode = darkMode
                };

                GuardarSesionJSON(sesion);

                MostrarPrincipal(sesion);
                login.Close();
            };

            login.Show();
        }

        private void MostrarPrincipal(SesionUsuario sesion)
        {
            var principal = new FormPrincipal(sesion.Usuario, sesion.DarkMode, ObtenerControlUsuario(sesion.Usuario));

            principal.OnCerrarSesion += () =>
            {
                BorrarSesionJSON();
                MostrarLogin();
                principal.Close();
            };

            principal.Show();
        }
    }


}
