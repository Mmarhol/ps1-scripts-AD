
# Version : 1.3
# Description : Script pour cr�er un utilisateur dans Active Directory, mode debug, cr�er/mappage de partage personnel et loguer les actions/erreurs

# D�finition du chemin du fichier de log
$errorLogFile = "C:\logs\user_creation_error_log.txt"

# Ici on v�rifie si le fichier de log existe, si il n'existe pas on le cr�e, si il existe on ne fais rien
if (-not (Test-Path $errorLogFile)) {
    Write-Host "Fichier de log non trouv�, cr�ation..." -ForegroundColor Magenta
    New-Item -ItemType File -Path $errorLogFile -Force | Out-Null
    Write-Host "Fichier de log cr�� avec succ�s !" -ForegroundColor Green
} else {
    Write-Host "Fichier de log trouv� !" -ForegroundColor Green
}

$debug = $true

# Entrez un chemin d�acc�s vers votre fichier d�importation CSV
$ADUsers = Import-Csv "newusers.csv"

# On v�rifie le format de l'OU
function Validate-OUFormat {
    param (
        [string]$OU
    )
    # On v�rifie que l'OU est dans le format correct : 'OU=...,DC=...,DC=...'
    return $OU -match '^OU=.*?,DC=.*?,DC=.*?$'
}

# On parcourt chaque utilisateur dans le fichier CSV
foreach ($User in $ADUsers)
{
    # On assigne les valeurs des colonnes du fichier CSV � des variables
    $Username    = $User.username
    $Password    = $User.password
    $Firstname   = $User.firstname
    $Lastname    = $User.lastname
    $Department  = $User.department
    $OU          = $User.ou
    $DisplayName = "$Firstname $Lastname"
    $Name        = "$Lastname $Firstname"
    $SecurityGroup = $User.securityGroup

    # Mode debug activ�?
    if ($debug) {
        Write-Host "[DEBUG] Mode DEBUG actif !" -ForegroundColor Yellow
        Write-Host "[DEBUG] Traitement de l'utilisateur : $Username" -ForegroundColor Yellow
        Write-Host "[DEBUG] Pr�nom : $Firstname, Nom de famille : $Lastname, Nom d'affichage : $DisplayName, Nom complet : $Name" -ForegroundColor Yellow
        Write-Host "[DEBUG] OU : $OU, D�partement : $Department" -ForegroundColor Yellow
    }

    try {
        # Ici on v�rifie si les donn�es n�cessaires sont pr�sentes et valides
        if (-not $Username) {
            throw "Nom d'utilisateur manquant."
        }

        if (-not $Password) {
            throw "Mot de passe manquant."
        }

        if (-not $Firstname) {
            throw "Pr�nom manquant."
        }

        if (-not $Lastname) {
            throw "Nom de famille manquant."
        }

        if (-not $Department) {
            throw "D�partement manquant."
        }

        if (-not $OU) {
            throw "OU manquant."
        }
        if (-not $SecurityGroup) {
            throw "SecurityGroup manquant."
        }

        # On v�rifie si l'OU est dans le format correct
        if (-not (Validate-OUFormat $OU)) {
            throw "Le format de l'OU '$OU' est incorrect. Le format attendu est 'OU=...,DC=...,DC=...'."
        }

        # On v�rifie si le compte utilisateur existe d�j� dans Active Directory
        if (Get-ADUser -F {SamAccountName -eq $Username}) {
            # Si l�utilisateur existe, �dite un message d�avertissement
            Write-Warning "Le compte $Username existe d�j�."
            # Log l'avertissement
            Add-Content -Path $errorLogFile -Value "$(Get-Date) - Le compte $Username existe d�j�."
        } else {
            # Si l�utilisateur n�existe pas, cr�e un nouveau compte utilisateur
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

            Write-Host "Utilisateur $Username cr�� avec succ�s dans l'OU $OU." -ForegroundColor Green
            # Log la cr�ation de l'utilisateur
            Add-Content -Path $errorLogFile -Value "$(Get-Date) - Utilisateur $Username cr�� avec succ�s dans l'OU $OU."

            # Cr�e un partage personnel pour l'utilisateur et le mappe sur le lecteur P:
            # D�finit le chemin du r�pertoire personnel de l'utilisateur sur le serveur
            $HomeDirectory = "E:\partages_personnels\$Username$"
            
            # Cr�e le r�pertoire personnel sur le serveur
            New-Item -ItemType Directory -Path $HomeDirectory -Force
            
            # D�finit les permissions du r�pertoire pour l'utilisateur
            icacls $HomeDirectory /grant "$Username`:F"
            
            # Associe le r�pertoire personnel et le lecteur P: � l'utilisateur dans AD
            Set-ADUser -Identity $Username -HomeDirectory "\\SRV-AD\$Username$" -HomeDrive P:
            
            # Cr�e le partage r�seau pour le r�pertoire personnel de l'utilisateur
            New-SmbShare -Name "$Username$" -Path $HomeDirectory -FullAccess "$Username"
            
            # Affiche un message indiquant que le partage personnel a �t� cr�� et mapp�
            Write-Host "[OK] Partage personnel cr�� et mapp� pour $Username." -ForegroundColor Green
            # Log la cr�ation et le mappage du partage personnel
            Add-Content -Path $errorLogFile -Value "$(Get-Date) - [OK] Partage personnel cr�� et mapp� pour $Username."
            
            # Attribution du groupe de s�curit� en fonction des donn�es du fichier CSV
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
                Write-Host "Le groupe $group n'existe pas dans Active Directory. L'utilisateur $Username n'a pas �t� ajout� au groupe." -ForegroundColor Red
                Add-Content -Path $errorLogFile -Value "$(Get-Date) - Le groupe $group n'existe pas dans Active Directory. L'utilisateur $Username n'a pas �t� ajout� au groupe."
            }
        }
    } catch {
        # Affiche un message d'erreur en cas de probl�me lors de la cr�ation de l'utilisateur
        Write-Host "Erreur lors de la cr�ation de l'utilisateur $Username : $_" -ForegroundColor Red
        # Log l'erreur
        Add-Content -Path $errorLogFile -Value "$(Get-Date) - Erreur lors de la cr�ation de l'utilisateur $Username : $_"
    }
}
