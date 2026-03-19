while ($true) {
    # Check if there are any changes (modified, deleted, or untracked)
    $status = git status --porcelain
    if ($status) {
        Write-Host "Detected changes. Committing..."
        git add .
        $date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        git commit -m "Auto-commit: $date"
        Write-Host "Committed changes at $date."
    }
    
    # Wait for 10 seconds before checking again
    Start-Sleep -Seconds 10
}
