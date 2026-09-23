$gpg = "C:\Program Files (x86)\GnuPG\bin\gpg.exe"
$pass = "test1234"
$target = "C:\LabShare\dataset"
Get-ChildItem $target -Recurse -File | Where-Object { $_.Extension -ne ".gpg" -and $_.Name -notlike "_manifest*" } | ForEach-Object {
& $gpg --batch --yes --passphrase $pass -c --cipher-algo AES256 $_.FullName
Remove-Item $_.FullName -Force
Start-Sleep -Seconds 2
}