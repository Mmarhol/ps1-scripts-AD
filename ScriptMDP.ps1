
# Version : 1.1
# Description : Script pour r�initialiser un mot de passe et demander un changement lors de la prochaine connexion

# D�finition du chemin du fichier de log
$logFile = "C:\logs\password_reset_log.txt"

# On v�rifie si le fichier de log existe, sinon le cr�er
if (-not (Test-Path $logFile)) {
    Write-Host "Fichier de log non trouv�, cr�ation..." -ForegroundColor Magenta
    New-Item -ItemType File -Path $logFile -Force | Out-Null
    Write-Host "Fichier de log cr�� avec succ�s !" -ForegroundColor Green
} else {
    Write-Host "Fichier de log trouv� !" -ForegroundColor Green
}

try {
    # On demande le login de l'user
    $Identity = Read-Host -Prompt "Entrez l'identit� de l'utilisateur (nom pour la connexion par exemple t.test)" 

    # On r�cup l'utilisateur 
    try {
        $ADUser = Get-ADUser -Identity $Identity -ErrorAction Stop
    } catch {
        Write-Error "Impossible de trouver un utilisateur avec l'identit� '$Identity'. V�rifiez que l'identit� est correcte."
        exit
    }

    # On demande la raison du changement de mot de passe
    $Reason = Read-Host -Prompt "Veuillez sp�cifier une raison pour le changement de mot de passe"

    # Ici on s'assure que le new pwd respecte la longueur mini de caract�res (14)
    do {
        $NewPassword = Read-Host -Prompt "Entrez le nouveau mot de passe (minimum 14 caract�res)" -AsSecureString
        # Conversion de SecureString en cha�ne pour v�rifier la longueur
        $PasswordLength = (New-Object PSCredential "dummy", $NewPassword).GetNetworkCredential().Password.Length
        if ($PasswordLength -lt 14) {
            Write-Host "Le mot de passe doit comporter au moins 14 caract�res. Veuillez r�essayer." -ForegroundColor Red
        }
    } while ($PasswordLength -lt 14)

    # le mot de passe doit �tre chang� � la prochaine connexion
    $MustChangePasswordAtLogon = $true

    # On r�initialise le mot de passe avec le nouveau mot de passe
    Set-ADAccountPassword -Identity $ADUser -Reset -NewPassword $NewPassword
    Add-Content -Path $logFile -Value "$(Get-Date) - Mot de passe r�initialis� pour l'utilisateur $Identity. Raison: $Reason."

    # On unlock le compte AD
    Unlock-ADAccount -Identity $ADUser
    Add-Content -Path $logFile -Value "$(Get-Date) - Compte d�verrouill� pour l'utilisateur $Identity."

    # On demande le changement de mot de passe � la prochaine connexion
    Set-ADUser -Identity $ADUser -ChangePasswordAtLogon $MustChangePasswordAtLogon
    Add-Content -Path $logFile -Value "$(Get-Date) - Changement de mot de passe � la prochaine connexion d�fini pour l'utilisateur $Identity."

    Write-Host "Le mot de passe a �t� modifi� avec succ�s !" -ForegroundColor Green
} catch {
    Write-Host "Erreur lors de la r�initialisation du mot de passe pour l'utilisateur $Identity : $_" -ForegroundColor Red
}
