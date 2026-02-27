param(
  [Parameter(Mandatory)][string]
)
Get-ChildItem -Path  -Filter "*.png" |
  Rename-Item -NewName { .Name -replace ' ', '-' }
Write-Host "Done. Images renamed in: "
