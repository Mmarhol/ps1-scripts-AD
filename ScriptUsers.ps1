
# Version : 1.3
# Description : Script pour créer un utilisateur dans Active Directory, mode debug, créer/mappage de partage personnel et loguer les actions/erreurs

# Définition du chemin du fichier de log
$errorLogFile = "C:\logs\user_creation_error_log.txt"

# Ici on vérifie si le fichier de log existe, si il n'existe pas on le crée, si il existe on ne fais rien
if (-not (Test-Path $errorLogFile)) {
    Write-Host "Fichier de log non trouvé, création..." -ForegroundColor Magenta
    New-Item -ItemType File -Path $errorLogFile -Force | Out-Null
    Write-Host "Fichier de log créé avec succès !" -ForegroundColor Green
} else {
    Write-Host "Fichier de log trouvé !" -ForegroundColor Green
}

$debug = $true

# Entrez un chemin d’accès vers votre fichier d’importation CSV
$ADUsers = Import-Csv "newusers.csv"

# On vérifie le format de l'OU
function Validate-OUFormat {
    param (
        [string]$OU
    )
    # On vérifie que l'OU est dans le format correct : 'OU=...,DC=...,DC=...'
    return $OU -match '^OU=.*?,DC=.*?,DC=.*?$'
}

# On parcourt chaque utilisateur dans le fichier CSV
foreach ($User in $ADUsers)
{
    # On assigne les valeurs des colonnes du fichier CSV à des variables
    $Username    = $User.username
    $Password    = $User.password
    $Firstname   = $User.firstname
    $Lastname    = $User.lastname
    $Department  = $User.department
    $OU          = $User.ou
    $DisplayName = "$Firstname $Lastname"
    $Name        = "$Lastname $Firstname"
    $SecurityGroup = $User.securityGroup

    # Mode debug activé?
    if ($debug) {
        Write-Host "[DEBUG] Mode DEBUG actif !" -ForegroundColor Yellow
        Write-Host "[DEBUG] Traitement de l'utilisateur : $Username" -ForegroundColor Yellow
        Write-Host "[DEBUG] Prénom : $Firstname, Nom de famille : $Lastname, Nom d'affichage : $DisplayName, Nom complet : $Name" -ForegroundColor Yellow
        Write-Host "[DEBUG] OU : $OU, Département : $Department" -ForegroundColor Yellow
    }

    try {
        # Ici on vérifie si les données nécessaires sont présentes et valides
        if (-not $Username) {
            throw "Nom d'utilisateur manquant."
        }

        if (-not $Password) {
            throw "Mot de passe manquant."
        }

        if (-not $Firstname) {
            throw "Prénom manquant."
        }

        if (-not $Lastname) {
            throw "Nom de famille manquant."
        }

        if (-not $Department) {
            throw "Département manquant."
        }

        if (-not $OU) {
            throw "OU manquant."
        }
        if (-not $SecurityGroup) {
            throw "SecurityGroup manquant."
        }

        # On vérifie si l'OU est dans le format correct
        if (-not (Validate-OUFormat $OU)) {
            throw "Le format de l'OU '$OU' est incorrect. Le format attendu est 'OU=...,DC=...,DC=...'."
        }

        # On vérifie si le compte utilisateur existe déjà dans Active Directory
        if (Get-ADUser -F {SamAccountName -eq $Username}) {
            # Si l’utilisateur existe, édite un message d’avertissement
            Write-Warning "Le compte $Username existe déjà."
            # Log l'avertissement
            Add-Content -Path $errorLogFile -Value "$(Get-Date) - Le compte $Username existe déjà."
        } else {
            # Si l’utilisateur n’existe pas, crée un nouveau compte utilisateur
            New-ADUser `
                -SamAccountName $User.username `
                -GivenName $User.firstname `
                -Surname $User.lastname `
                -Name "$($User.lastname) $($User.firstname)" `
                -Enabled $True `
                -ChangePasswordAtLogon $True `
                -DisplayName "$($User.firstname) $($User.lastname)" `
                -Department $User.department `
                -Path $User.ou `
                -AccountPassword (ConvertTo-SecureString $User.password -AsPlainText -Force)

            Write-Host "Utilisateur $Username créé avec succès dans l'OU $OU." -ForegroundColor Green
            # Log la création de l'utilisateur
            Add-Content -Path $errorLogFile -Value "$(Get-Date) - Utilisateur $Username créé avec succès dans l'OU $OU."

            # Crée un partage personnel pour l'utilisateur et le mappe sur le lecteur P:
            # Définit le chemin du répertoire personnel de l'utilisateur sur le serveur
            $HomeDirectory = "E:\partages_personnels\$Username$"
            
            # Crée le répertoire personnel sur le serveur
            New-Item -ItemType Directory -Path $HomeDirectory -Force
            
            # Définit les permissions du répertoire pour l'utilisateur
            icacls $HomeDirectory /grant "$Username`:F"
            
            # Associe le répertoire personnel et le lecteur P: à l'utilisateur dans AD
            Set-ADUser -Identity $Username -HomeDirectory "\\SRV-AD\$Username$" -HomeDrive P:
            
            # Crée le partage réseau pour le répertoire personnel de l'utilisateur
            New-SmbShare -Name "$Username$" -Path $HomeDirectory -FullAccess "$Username"
            
            # Affiche un message indiquant que le partage personnel a été créé et mappé
            Write-Host "[OK] Partage personnel créé et mappé pour $Username." -ForegroundColor Green
            # Log la création et le mappage du partage personnel
            Add-Content -Path $errorLogFile -Value "$(Get-Date) - [OK] Partage personnel créé et mappé pour $Username."
            
            # Attribution du groupe de sécurité en fonction des données du fichier CSV
            $group = $User.securityGroup
            if ($debug) {
                Write-Host "[DEBUG] GROUPE DE L'USER  : $group"
            }
            $groupExists = Get-ADGroup -Filter {Name -eq $group}
            if ($debug) {
                Write-Host "[DEBUG] groupExists  : $groupExists"
            }
            if ($groupExists) {
                Add-ADGroupMember -Identity $groupExists -Members $Username
            } else {
                Write-Host "Le groupe $group n'existe pas dans Active Directory. L'utilisateur $Username n'a pas été ajouté au groupe." -ForegroundColor Red
                Add-Content -Path $errorLogFile -Value "$(Get-Date) - Le groupe $group n'existe pas dans Active Directory. L'utilisateur $Username n'a pas été ajouté au groupe."
            }
        }
    } catch {
        # Affiche un message d'erreur en cas de problème lors de la création de l'utilisateur
        Write-Host "Erreur lors de la création de l'utilisateur $Username : $_" -ForegroundColor Red
        # Log l'erreur
        Add-Content -Path $errorLogFile -Value "$(Get-Date) - Erreur lors de la création de l'utilisateur $Username : $_"
    }
}
