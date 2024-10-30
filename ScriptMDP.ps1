
# Version : 1.1
# Description : Script pour réinitialiser un mot de passe et demander un changement lors de la prochaine connexion

# Définition du chemin du fichier de log
$logFile = "C:\logs\password_reset_log.txt"

# On vérifie si le fichier de log existe, sinon le créer
if (-not (Test-Path $logFile)) {
    Write-Host "Fichier de log non trouvé, création..." -ForegroundColor Magenta
    New-Item -ItemType File -Path $logFile -Force | Out-Null
    Write-Host "Fichier de log créé avec succès !" -ForegroundColor Green
} else {
    Write-Host "Fichier de log trouvé !" -ForegroundColor Green
}

try {
    # On demande le login de l'user
    $Identity = Read-Host -Prompt "Entrez l'identité de l'utilisateur (nom pour la connexion par exemple t.test)" 

    # On récup l'utilisateur 
    try {
        $ADUser = Get-ADUser -Identity $Identity -ErrorAction Stop
    } catch {
        Write-Error "Impossible de trouver un utilisateur avec l'identité '$Identity'. Vérifiez que l'identité est correcte."
        exit
    }

    # On demande la raison du changement de mot de passe
    $Reason = Read-Host -Prompt "Veuillez spécifier une raison pour le changement de mot de passe"

    # Ici on s'assure que le new pwd respecte la longueur mini de caractères (14)
    do {
        $NewPassword = Read-Host -Prompt "Entrez le nouveau mot de passe (minimum 14 caractères)" -AsSecureString
        # Conversion de SecureString en chaîne pour vérifier la longueur
        $PasswordLength = (New-Object PSCredential "dummy", $NewPassword).GetNetworkCredential().Password.Length
        if ($PasswordLength -lt 14) {
            Write-Host "Le mot de passe doit comporter au moins 14 caractères. Veuillez réessayer." -ForegroundColor Red
        }
    } while ($PasswordLength -lt 14)

    # le mot de passe doit être changé à la prochaine connexion
    $MustChangePasswordAtLogon = $true

    # On réinitialise le mot de passe avec le nouveau mot de passe
    Set-ADAccountPassword -Identity $ADUser -Reset -NewPassword $NewPassword
    Add-Content -Path $logFile -Value "$(Get-Date) - Mot de passe réinitialisé pour l'utilisateur $Identity. Raison: $Reason."

    # On unlock le compte AD
    Unlock-ADAccount -Identity $ADUser
    Add-Content -Path $logFile -Value "$(Get-Date) - Compte déverrouillé pour l'utilisateur $Identity."

    # On demande le changement de mot de passe à la prochaine connexion
    Set-ADUser -Identity $ADUser -ChangePasswordAtLogon $MustChangePasswordAtLogon
    Add-Content -Path $logFile -Value "$(Get-Date) - Changement de mot de passe à la prochaine connexion défini pour l'utilisateur $Identity."

    Write-Host "Le mot de passe a été modifié avec succès !" -ForegroundColor Green
} catch {
    Write-Host "Erreur lors de la réinitialisation du mot de passe pour l'utilisateur $Identity : $_" -ForegroundColor Red
}
