# Define variables
$tenantId = "71bd40cc-f247-42ec-8be3-b26ab2c3e15e"
$clientId = "cfbc2f0e-c7af-473f-beaf-c92681d5c759"
$certThumbprint = "D4BF913C3E4B14156E5A7BEE56315FCBFC270676"
$functionAppUrl = "https://functionapp1111.azurewebsites.net/"

# Import the certificate from the local machine store
$cert = Get-Item -Path "Cert:\CurrentUser\My\$certThumbprint"

# Prepare the XML payload
$xmlPayload = @"
<root>
    <element>Value</element>
</root>
"@

# Get an access token using the certificate
$tokenResponse = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body @{
        client_id = $clientId
        scope = "https://management.azure.com/.default"
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        client_assertion = [System.Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12))
        grant_type = "client_credentials"
    }

$accessToken = $tokenResponse.access_token

# Make the HTTP request to the Function App
$response = Invoke-RestMethod -Method Post -Uri $functionAppUrl `
    -Headers @{ "Authorization" = "Bearer $accessToken" } `
    -ContentType "application/xml" `
    -Body $xmlPayload

# Output the response
Write-Output $response