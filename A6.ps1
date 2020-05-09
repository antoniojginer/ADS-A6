#Funciones de apoyo
function Set-Inheritance ($path,$inherit) {
    $acl = Get-ACL "$path"
    $acl.SetAccessRuleProtection($true, $inherit)
    Set-ACL "$Path" $acl
}


function Add-Ace ($path,$group,$permission) {
    $acl = Get-ACL "$Path"
    $sid = (Get-ADGroup -filter {name -eq $group}).sid

    $rights = [System.Security.AccessControl.FileSystemRights]$permission 
    $inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagationFlag = [System.Security.AccessControl.PropagationFlags]'None'
    $type =[System.Security.AccessControl.AccessControlType]'Allow'

    $ace = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($sid, $rights, $inheritanceFlag, $propagationFlag, $type) 

    $acl.AddAccessRule($ace)
    Set-ACL "$Path" $acl
}



# RETO 1

Write-Host "RETO 1  -----------------------------------------------"

$nombre_unidad_temporal = "UO-Temp"
$dn_dominio             = "dc=admon,dc=lab"
$nombre_unidad_series   = "Series"
$dn_unidad_temporal     = "ou=UO-Temp,dc=admon,dc=lab"
$dn_unidad_series       = "ou=Series,ou=UO-Temp,dc=admon,dc=lab"

$ruta_carpeta           = "C:\Series-Temp"


# Búsqueda (y borrado) de la unidad
$unidad = Get-ADOrganizationalUnit -Filter { Name -eq $nombre_unidad_temporal } -SearchBase $dn_dominio `
            -SearchScope OneLevel

if ($unidad -ne $null) {
    Write-Host "La unidad $nombre_unidad_temporal ya existía en $dn_dominio. Eliminándola..."
    
    Remove-ADOrganizationalUnit $dn_unidad_temporal -Recursive -confirm:$false
    Write-Host "Eliminada"
}


# Creación de la unidad temporal en la raíz del dominio y sus subunidades:
New-ADOrganizationalUnit  $nombre_unidad_temporal  -Path $dn_dominio -ProtectedFromAccidentalDeletion:$false
Write-Host "Unidad organizativa '$nombre_unidad_temporal' creada en $dn_dominio"

New-ADOrganizationalUnit $nombre_unidad_series -Path $dn_unidad_temporal -ProtectedFromAccidentalDeletion:$false
Write-Host "Unidad organizativa '$nombre_unidad_series' creada en $dn_unidad_temporal"

New-ADOrganizationalUnit "Usuarios" -Path $dn_unidad_series -ProtectedFromAccidentalDeletion:$false
Write-Host "Unidad organizativa 'Usuarios' creada en $dn_unidad_series"

New-ADOrganizationalUnit "Roles" -Path $dn_unidad_series -ProtectedFromAccidentalDeletion:$false
Write-Host "Unidad organizativa 'Roles' creada en $dn_unidad_series"

New-ADOrganizationalUnit "Recursos" -Path $dn_unidad_series -ProtectedFromAccidentalDeletion:$false
Write-Host "Unidad organizativa 'Recursos' creada en $dn_unidad_series"


#Busqueda (y borrado) de la carpeta C:\Series-Temp

$carpeta = Test-Path $ruta_carpeta -PathType Container

if($carpeta){
    Write-Host "La carpeta $ruta_carpeta ya existía. Eliminándola..."

    Remove-Item $ruta_carpeta -Recurse -Confirm:$false
}

#Creación de la carpeta

Write-Host "Creando la carpeta $ruta_carpeta..."
New-Item $ruta_carpeta -ItemType "Directory"
Add-Ace -path $ruta_carpeta -group "Administradores" -permission "FullControl"
Set-Inheritance -Path $ruta_carpeta -inherit $false
Write-Host "$ruta_carpeta ha sido creada"

#RETO 2

Write-Host ""
Write-Host "RETO 2  -----------------------------------------------"

$lista_empleados_validos = @()
 Import-CSV -Path "C:\A6\empleados.csv" | ForEach-Object {

    [string]$nombre_usuario = $_.empleado
    

    Write-Host "Procesando la linea del empleado = $nombre_usuario"
   
    $linea_correcta = $true
    $usuario = Get-ADUser -Filter { Name -eq $nombre_usuario }
    if ($usuario) {
        $linea_correcta = $false
    }

    if ($linea_correcta) {
        $lista_empleados_validos += $nombre_usuario

        $contraseña = "Admon.lab.1"
        $dn_contenedor = "ou=Usuarios,ou=Series,ou=UO-Temp,dc=admon,dc=lab" # ESTA NO ES, HAY QUE CAMBIARLO!!!!
        $hash = Convertto-SecureString -AsPlainText $contraseña -Force

        New-ADUser -Name $nombre_usuario -AccountPassword $hash -ChangePasswordAtLogon $false -Enabled $true -Path $dn_contenedor
        Write-Host "    Usuario $nombre_usuario creado en $dn_contenedor"
        Write-Host ""
    } else {
        Write-Host "    Línea incorrecta: usuario ya se ha creado!"
        Write-Host ""
    }
}

# RETO 3 (Parcial: Mostrar roles por cada proyecto, controlando sólo el error de rol no válido)

Write-Host ""
Write-Host "RETO 3  -----------------------------------------------"

$CSV = "C:\A6\proyectos-roles.csv"
$ROLES_VALIDOS = @("direccion","guion","reparto","imagen","sonido","montaje")
$lista_proyectos  = @()
$lista_roles_validos = @()
$lista_combinacion_validos = @()

import-csv -path $CSV  | ForEach-Object { 

    $proyecto = $_.proyecto
    $roles    = $_.roles

    $lista_roles = $roles -split "/"
    $ruta_carpeta_proyecto=$ruta_carpeta+"\"+$proyecto

    Write-Host "Procesando: Proyecto = $proyecto, Roles = $lista_roles"
   
    $linea_correcta = $true
    $error_linea = ""
    
    if(($proyecto -eq $null) -or ($proyecto -eq "")){
        $linea_correcta=$false
        $error_linea += "        Nombre del proyecto vacio."
    }else{  
        if($proyecto -in $lista_proyectos){
            $linea_correcta=$false
            $error_linea += "        $proyecto ya habia sido creado"
        } else{
            foreach ($rol in $lista_roles) {
                if ($rol -notin $ROLES_VALIDOS) {
                    $linea_correcta = $false
                    $error_linea += "        Rol $rol no válido."
                }
            }
        }
    }      

    if ($linea_correcta) {
        $lista_proyectos += $proyecto
        New-Item $ruta_carpeta_proyecto -ItemType "Directory"
        Add-Ace -path $ruta_carpeta_proyecto -group "Administradores" -permission "FullControl"
        Set-Inheritance -Path $ruta_carpeta_proyecto -inherit $false
        foreach ($rol in $lista_roles) {
            $nombre_grupo = "$proyecto-$rol"
            Write-Host "    $rol"
            New-ADGroup -Name $nombre_grupo -Path "ou=Roles,ou=Series,ou=UO-Temp,dc=admon,dc=lab" -GroupScope Global
            Write-Host "        $nombre_grupo creado"
            if($nombre_grupo -notin $lista_combinacion_validos){
                $lista_combinacion_validos += $nombre_grupo
            }
            
            if($rol -notin $lista_roles_validos){
                $lista_roles_validos += $rol
            }
            
        }
        Write-Host ""
    } else {
        Write-Host "ERROR: $error_linea"
        Write-Host ""
    }

}

# RETO 4 ------------------

Write-host ""
Write-Host "RETO 4  -----------------------------------------------"

$CSV = "C:\A6\participacion.csv"
$ROLES_VALIDOS = @("direccion","guion","reparto","imagen","sonido","montaje")

import-csv -path $CSV  | ForEach-Object {
    

    $proyecto = $_.proyecto
    $rol    = $_.rol
    $empleados = $_.empleados

    $lista_empleados = $empleados -split "/"
    $linea_error = ""
    

    $linea_correcta = $true

    Write-host "Procesando: $proyecto, $rol, $empleados"

    if(($proyecto -eq $null) -or ($proyecto -eq "")){
        $linea_correcta = $false
        $linea_error += "        Proyecto vacio `n"
    } else{
        if($proyecto -notin $lista_proyectos){
            $linea_correcta = $false
            $linea_error += "        Proyecto no valido `n"
    }
    }
    if($rol -notin $ROLES_VALIDOS){
        $linea_correcta = $false
        $linea_error += "        Rol vacio o no válido `n"
    }
    if(($empleados -eq $null) -or ($empleados -eq "")){
        $linea_correcta = $false
        $linea_error +="        Lista de empleados vacía `n"
    } else{        
        foreach($e in $lista_empleados){
            if($e -notin $lista_empleados_validos){
                $linea_correcta = $false
                $linea_error += "        Empleado no válido `n"
                Break
            }
        }
    }

    if($linea_correcta){
        Write-Host "        Añadiendo $proyecto-$rol"
        Add-ADGroupMember -Identity "$proyecto-$rol" -Members $lista_empleados
        Write-Host ""
    } else{
        Write-host "Error: `n$linea_error"
    }

}

    Write-host ""
    Write-host ""







#  RETO 5 ------------------------------------------------------------------------------------------
Write-Host "RETO 5  -----------------------------------------------"
Write-host ""

$CSV = "C:\A6\niveles.csv"
$niveles_validos = @("Completo", "Trabajo", "Edicion", "Lectura")
$ROLES_VALIDOS = @("direccion","guion","reparto","imagen","sonido","montaje")
$lista_acl_creados = @()


import-csv -path $CSV  | ForEach-Object {

    $proyecto = $_.proyecto
    $nivel    = $_.nivel
    $rol = $_.roles

    $linea_error = ""
    $lista_roles = @()

    $linea_correcta = $true
    
    Write-host "Procesando: $proyecto, $nivel, $rol"

    if(($proyecto -eq $null) -or ($proyecto -eq "")){
        $linea_error += "        Proyecto vacio `n"
        $linea_correcta = $false
    } else{
        if($proyecto -notin $lista_proyectos){
            $linea_error += "        $proyecto no es un nombre de proyecto valido `n"
            $linea_correcta = $false
        }
    }
        
    if(($nivel -eq $null) -or ($nivel -eq "")){
        $linea_error += "        Nivel vacio `n"
        $linea_correcta = $false
    } else{
        if($nivel -notin $niveles_validos){
            $linea_error += "        $nivel no es un nivel valido `n"
            $linea_correcta = $false
        }
    }

    if($rol -eq $null){
        $linea_error += "        Rol vacio `n"
        $linea_correcta = $false
    } else{        
        $lista_roles = $rol -split "/"
        foreach($r in $lista_roles){
            if($r -notin $lista_roles_validos){
                $linea_error += "        $rol no es un rol valido `n"
                $linea_correcta = $false
            }
            $nombre_grupo = "$proyecto-$r"
            if($nombre_grupo -notin $lista_combinacion_validos){
                $linea_error += "        $nombre_grupo no es un grupo valido `n"
                $linea_correcta = $false
            }
        }
        
    }
    
    if($linea_correcta){
        $ruta_carpeta = "C:\Series-Temp"
        $ruta_carpeta_proyecto=$ruta_carpeta+"\"+$proyecto
        $nombre_acl = "ACL-$proyecto-$nivel"

        Write-Host "        Metiendo $nombre_acl"
        
        if($nombre_acl -notin $lista_acl_creados){
            $lista_acl_creados += $nombre_acl
            New-ADGroup -Name $nombre_acl -GroupScope DomainLocal -Path "ou=Recursos,ou=Series,ou=UO-Temp,dc=admon,dc=lab"
            
        }else{
            Write-Host "        $nombre_acl ya estaba creado"
        }
        foreach($r in $lista_roles){
            $nombre_grupo = "$proyecto-$r"
            Add-ADGroupMember -Identity "$nombre_acl" -Members $nombre_grupo
        }
        

        switch($nivel){
            "Completo" {Add-ACE -Path $ruta_carpeta_proyecto -group $nombre_acl -permission "FullControl"}
            "Trabajo" {Add-ACE -Path $ruta_carpeta_proyecto -group $nombre_acl -permission "Modify"}
            "Edicion"{Add-ACE -Path $ruta_carpeta_proyecto -group $nombre_acl -permission "Write"}
            "Lectura"{Add-ACE -Path $ruta_carpeta_proyecto -group $nombre_acl -permission "ReadAndExecute"}
        }
        Write-host ""
    } else{
        Write-Host "Error: `n$linea_error"
    }
        
}

    
