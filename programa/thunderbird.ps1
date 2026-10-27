param([string]$ThunderbirdExe, [string]$Perfil, [switch]$Abrir, [switch]$SoloAbrir)
$ErrorActionPreference = 'Stop'
$raiz = Split-Path $PSScriptRoot -Parent
if (-not $Perfil) { $Perfil = Join-Path $raiz 'datos/thunderbird' }
$Perfil = [IO.Path]::GetFullPath($Perfil)
$datos = [IO.Path]::GetFullPath((Join-Path $raiz 'datos'))
if (-not $Perfil.StartsWith($datos + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) { throw 'El perfil debe quedar dentro de datos.' }
if (-not $ThunderbirdExe -or -not (Test-Path $ThunderbirdExe)) { throw 'No encuentro Thunderbird.' }
$ThunderbirdExe = (Resolve-Path $ThunderbirdExe).Path
$marca = Join-Path $Perfil 'emailchecker.json'
function Abrir-Perfil {
    $abierto = Get-CimInstance Win32_Process -Filter "name='thunderbird.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -and $_.CommandLine.IndexOf($Perfil, [StringComparison]::OrdinalIgnoreCase) -ge 0 }
    if (-not $abierto) { Start-Process -FilePath $ThunderbirdExe -ArgumentList @('-no-remote','-profile',('"' + $Perfil + '"')) }
}
if ($SoloAbrir) {
    if (-not (Test-Path $marca) -or (Get-Content -Raw $marca | ConvertFrom-Json).application -ne 'EmailChecker') { throw 'Primero ejecuta la instalacion de EmailChecker.' }
    Abrir-Perfil
    return
}
if ((Test-Path $Perfil) -and -not (Test-Path $marca) -and (Get-ChildItem -Force $Perfil)) { throw 'Ese perfil contiene datos ajenos a EmailChecker.' }
if (Test-Path $marca) {
    if ((Get-Content -Raw $marca | ConvertFrom-Json).application -ne 'EmailChecker') { throw 'Perfil no reconocido.' }
}
New-Item -ItemType Directory -Force -Path $Perfil | Out-Null
$utf8 = [Text.UTF8Encoding]::new($false)
function Guardar($Nombre, $Texto) { [IO.File]::WriteAllText((Join-Path $Perfil $Nombre), $Texto, $utf8) }
if (-not (Test-Path $marca)) { Guardar 'emailchecker.json' '{"application":"EmailChecker"}' }
$lock = Join-Path $Perfil 'parent.lock'
if (Test-Path $lock) {
    try { $f = [IO.File]::Open($lock, 'Open', 'ReadWrite', 'None'); $f.Dispose() }
    catch { throw 'Cierra solo el Thunderbird de EmailChecker antes de reconfigurarlo.' }
}
$cuentas = Get-Content -Raw -Encoding UTF8 (Join-Path $datos 'cuentas/credentials.json') | ConvertFrom-Json
foreach ($usuario in @('docente','alumno')) {
    if (-not $cuentas.PSObject.Properties[$usuario + '@empresa.lab'].Value) { throw 'Falta una cuenta del servidor.' }
}

# Se usa el cifrado de Thunderbird; las contrasenas no van a prefs.js.
if (-not ('EmailCheckerNss' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
public static class EmailCheckerNss {
  [StructLayout(LayoutKind.Sequential)] public struct Item { public int type; public IntPtr data; public uint len; }
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern bool SetDllDirectory(string path);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern IntPtr LoadLibrary(string path);
  [DllImport("nss3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int NSS_InitReadWrite([MarshalAs(UnmanagedType.LPUTF8Str)] string path);
  [DllImport("nss3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int NSS_Shutdown();
  [DllImport("nss3.dll", CallingConvention=CallingConvention.Cdecl)] static extern IntPtr PK11_GetInternalKeySlot();
  [DllImport("nss3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int PK11_NeedUserInit(IntPtr slot);
  [DllImport("nss3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int PK11_InitPin(IntPtr slot, string oldPin, string newPin);
  [DllImport("nss3.dll", CallingConvention=CallingConvention.Cdecl)] static extern void PK11_FreeSlot(IntPtr slot);
  [DllImport("nss3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int PK11SDR_EncryptWithMechanism(IntPtr slot, ref Item key, uint mechanism, ref Item input, ref Item output, IntPtr context);
  [DllImport("nss3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int PK11SDR_Encrypt(ref Item key, ref Item input, ref Item output, IntPtr context);
  [DllImport("nss3.dll", CallingConvention=CallingConvention.Cdecl)] static extern int PK11SDR_Decrypt(ref Item input, ref Item output, IntPtr context);
  [DllImport("nss3.dll", CallingConvention=CallingConvention.Cdecl)] static extern void SECITEM_ZfreeItem(ref Item item, int freeItem);
  static bool ready;
  public static void Open(string folder, string profile) {
    SetDllDirectory(folder);
    if (LoadLibrary(Path.Combine(folder,"nss3.dll")) == IntPtr.Zero) throw new Exception("No se pudo cargar el cifrado de Thunderbird de 64 bits.");
    if (NSS_InitReadWrite("sql:" + profile) != 0) throw new Exception("No se pudo abrir el almacen de claves del perfil.");
    ready = true;
    IntPtr slot = PK11_GetInternalKeySlot();
    if (slot == IntPtr.Zero) throw new Exception("No se pudo preparar el almacen de claves.");
    try { if (PK11_NeedUserInit(slot) != 0 && PK11_InitPin(slot,null,"") != 0) throw new Exception("No se pudo inicializar el cifrado."); }
    finally { PK11_FreeSlot(slot); }
  }
  public static string Transform(string value, bool decrypt) {
    byte[] bytes = decrypt ? Convert.FromBase64String(value) : Encoding.UTF8.GetBytes(value);
    Item input = new Item { data=Marshal.AllocHGlobal(bytes.Length), len=(uint)bytes.Length };
    Item output = new Item(); Item key = new Item();
    Marshal.Copy(bytes,0,input.data,bytes.Length);
    try {
      int status;
      if (decrypt) status = PK11SDR_Decrypt(ref input,ref output,IntPtr.Zero);
      else {
        try { status = PK11SDR_EncryptWithMechanism(IntPtr.Zero,ref key,0x1082,ref input,ref output,IntPtr.Zero); }
        catch (EntryPointNotFoundException) { status = PK11SDR_Encrypt(ref key,ref input,ref output,IntPtr.Zero); }
      }
      if (status != 0) throw new Exception("No se pudo guardar una contrasena con NSS.");
      byte[] result = new byte[output.len]; Marshal.Copy(output.data,result,0,result.Length);
      return decrypt ? Encoding.UTF8.GetString(result) : Convert.ToBase64String(result);
    } finally { SECITEM_ZfreeItem(ref output,0); for(int i=0;i<bytes.Length;i++) Marshal.WriteByte(input.data,i,0); Marshal.FreeHGlobal(input.data); Array.Clear(bytes,0,bytes.Length); }
  }
  public static void Close() { if (ready) NSS_Shutdown(); ready=false; SetDllDirectory(null); }
}
'@
}
$logins = @()
$ahora = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
try {
    [EmailCheckerNss]::Open((Split-Path $ThunderbirdExe), $Perfil)
    foreach ($usuario in @('docente','alumno')) {
        $direccion = $usuario + '@empresa.lab'
        $password = [string]$cuentas.PSObject.Properties[$direccion].Value
        $nombreCifrado = [EmailCheckerNss]::Transform($direccion, $false)
        $claveCifrada = [EmailCheckerNss]::Transform($password, $false)
        if ([EmailCheckerNss]::Transform($claveCifrada, $true) -cne $password) { throw 'No se pudo verificar la contrasena cifrada.' }
        foreach ($protocolo in @('imap','smtp')) {
            $origen = $protocolo + '://127.0.0.1'
            $logins += @{id=$logins.Count+1;hostname=$origen;httpRealm=$origen;formSubmitURL=$null;usernameField='';passwordField='';encryptedUsername=$nombreCifrado;encryptedPassword=$claveCifrada;guid=([guid]::NewGuid().ToString('B'));encType=1;timeCreated=$ahora;timeLastUsed=$ahora;timePasswordChanged=$ahora;timesUsed=0}
        }
    }
    Guardar 'logins.json' (@{version=3;nextId=5;logins=$logins} | ConvertTo-Json -Depth 5)
} finally { [EmailCheckerNss]::Close(); $password = $null; $cuentas = $null }

$prefs = [ordered]@{
    'mail.accountmanager.accounts'='account1,account2,account3'; 'mail.accountmanager.defaultaccount'='account1'; 'mail.accountmanager.localfoldersserver'='server3'
    'mail.smtpservers'='smtp1,smtp2'; 'mail.smtp.defaultserver'='smtp1'; 'mail.shell.checkDefaultClient'=$false; 'mailnews.start_page.enabled'=$false
    'mail.account.account3.server'='server3'; 'mail.server.server3.type'='none'; 'mail.server.server3.hostname'='Local Folders'; 'mail.server.server3.userName'='nobody'; 'mail.server.server3.name'='Carpetas locales'
    'mail.server.server3.directory'=(Join-Path $Perfil 'Mail/Local Folders')
}
$numero = 0
foreach ($usuario in @('docente','alumno')) {
    $numero++
    $direccion = $usuario + '@empresa.lab'
    $prefs["mail.account.account$numero.server"] = "server$numero"
    $prefs["mail.account.account$numero.identities"] = "id$numero"
    $server = @{type='imap';hostname='127.0.0.1';port=1993;userName=$direccion;name=$direccion;socketType=3;authMethod=3;login_at_startup=$true;check_new_mail=$true;directory=(Join-Path $Perfil "ImapMail/$usuario")}
    foreach ($key in $server.Keys) { $prefs["mail.server.server$numero.$key"] = $server[$key] }
    $smtp = @{hostname='127.0.0.1';port=465;username=$direccion;try_ssl=3;authMethod=3;description=$direccion}
    foreach ($key in $smtp.Keys) { $prefs["mail.smtpserver.smtp$numero.$key"] = $smtp[$key] }
    $prefs["mail.identity.id$numero.useremail"] = $direccion
    $prefs["mail.identity.id$numero.fullName"] = "$usuario EmailChecker"
    $prefs["mail.identity.id$numero.smtpServer"] = "smtp$numero"
    $uri = 'imap://' + [Uri]::EscapeDataString($direccion) + '@127.0.0.1:1993/'
    foreach ($entry in @{fcc_folder='Sent';draft_folder='Drafts';archive_folder='Archives';stationery_folder='Templates'}.GetEnumerator()) { $prefs["mail.identity.id$numero.$($entry.Key)"] = $uri + $entry.Value }
}
$lineas = foreach ($entry in $prefs.GetEnumerator()) { 'user_pref(' + (ConvertTo-Json ([string]$entry.Key) -Compress) + ', ' + (ConvertTo-Json $entry.Value -Compress) + ');' }
Guardar 'prefs.js' (($lineas -join "`n") + "`n")
$pem = Get-Content -Raw (Join-Path $datos 'cuentas/cert.pem')
$der = [Convert]::FromBase64String(($pem -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s',''))
$sha = [Security.Cryptography.SHA256]::Create()
try { $huella = [BitConverter]::ToString($sha.ComputeHash($der)).Replace('-',':') } finally { $sha.Dispose() }
$excepciones = foreach ($puerto in @(465,1993)) { "127.0.0.1:${puerto}:`tOID.2.16.840.1.101.3.4.2.1`t$huella`t" }
Guardar 'cert_override.txt' ("# EmailChecker: solo el certificado local y sus dos puertos.`n" + ($excepciones -join "`n") + "`n")
Write-Host 'Thunderbird configurado: dos cuentas, TLS y contrasenas guardadas.'
if ($Abrir) { Abrir-Perfil }
