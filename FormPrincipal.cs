using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Galeria
{
    public partial class FormPrincipal : Form
    {
        public event Action OnCerrarSesion;

        public FormPrincipal(string user, bool darkMode, string control)
        {
            InitializeComponent();
        }
    }
}
