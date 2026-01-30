terraform {
  required_providers {
    http = {
      source  = "hashicorp/http"
      version = "~> 3.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

resource "random_password" "ad_password" {
  length           = 20
  special          = true
  override_special = "#%&*()-_=+[]{}<>" # Avoid quotes/slashes/dollar that break scripts
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
}

resource "aws_eip" "server_ip" {
  domain = "vpc"
}

resource "random_integer" "subnet_octet" {
  min = 50
  max = 250
}

resource "tls_private_key" "ca_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca_cert" {
  private_key_pem = tls_private_key.ca_key.private_key_pem

  subject {
    common_name  = "LDAP-Lab-Root-CA"
    organization = "LDAP Lab"
  }

  validity_period_hours = 8760
  is_ca_certificate     = true

  allowed_uses = [
    "cert_signing",
    "crl_signing",
  ]
}

resource "tls_private_key" "server_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "server_req" {
  private_key_pem = tls_private_key.server_key.private_key_pem

  subject {
    common_name  = "*.${var.domain_name}"
    organization = "LDAP Lab"
  }

  dns_names    = ["*.${var.domain_name}", "${var.domain_name}"]
  ip_addresses = [aws_eip.server_ip.public_ip]
}

resource "tls_locally_signed_cert" "server_cert" {
  cert_request_pem   = tls_cert_request.server_req.cert_request_pem
  ca_private_key_pem = tls_private_key.ca_key.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca_cert.cert_pem

  validity_period_hours = 8760

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "local_file" "ca_pem_file" {
  content  = tls_self_signed_cert.ca_cert.cert_pem
  filename = "${path.module}/ca.pem"
}

data "http" "ip_check" {
  url = "http://checkip.amazonaws.com/"
}

data "aws_vpcs" "default_vpcs" {
  filter {
    name   = "isDefault"
    values = ["true"]
  }
}

data "aws_vpc" "default" {
  id = data.aws_vpcs.default_vpcs.ids[0]
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "windows_2022" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["Windows_Server-2022-English-Full-Base-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  dc_components = split(".", var.domain_name)
  dc_formatted  = join(",", [for c in local.dc_components : "dc=${c}"])
  random_cidr = cidrsubnet(data.aws_vpc.default.cidr_block, 8, random_integer.subnet_octet.result)
  final_password = var.password != "" ? var.password : random_password.ad_password.result
}

resource "aws_subnet" "new_subnet" {
  vpc_id            = data.aws_vpcs.default_vpcs.ids[0]
  cidr_block        = local.random_cidr
  availability_zone = data.aws_availability_zones.available.names[0]
}

resource "aws_instance" "windows_server" {
  ami           = data.aws_ami.windows_2022.id
  instance_type = var.instance_type
  
  vpc_security_group_ids = ["${aws_security_group.windows_server.id}"]
  subnet_id              = aws_subnet.new_subnet.id

  user_data = <<-EOF
    <powershell>
    Start-Transcript -Path "C:\terraform.log" -Append
    $adminPass = "${local.final_password}"
    net user Administrator $adminPass /active:yes

    # 1. Install Chocolatey & OpenSSL(via Git)
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    choco install git -y --no-progress
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

    # 2. Write PEM files
    $certContent = @"
${tls_locally_signed_cert.server_cert.cert_pem}
"@
    $certContent | Out-File -Encoding ASCII "C:\ad_cert.crt"

    $keyContent = @"
${tls_private_key.server_key.private_key_pem}
"@
    $keyContent | Out-File -Encoding ASCII "C:\ad_key.pem"

    $caContent = @"
${tls_self_signed_cert.ca_cert.cert_pem}
"@
    $caContent | Out-File -Encoding ASCII "C:\root_ca.pem"

    # 3. Create & Import PFX
    Import-Certificate -FilePath "C:\root_ca.pem" -CertStoreLocation Cert:\LocalMachine\Root

    & "C:\Program Files\Git\usr\bin\openssl.exe" pkcs12 -export -out "C:\server.pfx" -inkey "C:\ad_key.pem" -in "C:\ad_cert.crt" -passout pass:temp-password

    $pfxPass = ConvertTo-SecureString -String "temp-password" -Force -AsPlainText
    Import-PfxCertificate -FilePath "C:\server.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password $pfxPass

    # 4. Create Post-Promotion Script (So RDP is enabled for Remote Desktop Users Group)
    $PostScriptContent = @'
    Start-Transcript -Path "C:\post_promote.log"
    
    $Domain = (Get-WmiObject Win32_ComputerSystem).Domain
    $SysvolPath = "\\$Domain\SYSVOL\$Domain"
    
    #Wait for SYSVOL (DC is ready)
    while (!(Test-Path $SysvolPath)) { Write-Host "Waiting for SYSVOL..."; Start-Sleep 5 }

    Write-Host "Applying RDP Fix..."
    $LocalInf = "C:\rdp_fix.inf"
    $LocalDb  = "C:\local_policy.sdb"
    
    # Create a clean INF file with only the setting we need
    # *S-1-5-32-544 = Administrators
    # *S-1-5-32-555 = Remote Desktop Users
    $InfContent = @"
[Unicode]
Unicode=yes
[Version]
signature="$CHICAGO$"
Revision=1
[Privilege Rights]
SeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555
"@
    # Save as Unicode (Needed for Security Templates)
    $InfContent | Out-File -FilePath $LocalInf -Encoding Unicode

    # Apply immediately using SecEdit
    secedit /configure /db $LocalDb /cfg $LocalInf /areas USER_RIGHTS
    Write-Host "Local security policy forced successfully."

    # Update GPO so change persists after reboot
    Write-Host "Updating Domain Controller GPO for persistence..."
    $PolicyGUID  = "{6AC1786C-016F-11D2-945F-00C04fB984F9}"
    $GptTmplPath = "$SysvolPath\Policies\$PolicyGUID\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
    $GptIniPath  = "$SysvolPath\Policies\$PolicyGUID\GPT.INI"

    # Read existing content
    $Content = Get-Content -Path $GptTmplPath
    
    # Check if [Privilege Rights] exists
    if ($Content -match "\[Privilege Rights\]") {
        # Section exists. Check if the specific Right exists.
        if ($Content -match "SeRemoteInteractiveLogonRight") {
             # Right exists, append our SID if missing
             if ($Content -notmatch "\*S-1-5-32-555") {
                 $Content = $Content -replace "SeRemoteInteractiveLogonRight = .*", "$&,*S-1-5-32-555"
             }
        } else {
             # Section exists, but Right is missing. Insert it after the header.
             $Content = $Content -replace "\[Privilege Rights\]", "[Privilege Rights]`r`nSeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555"
        }
    } else {
        # Section missing entirely. Append to end.
        $Content += "`r`n[Privilege Rights]`r`nSeRemoteInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-555"
    }

    # Save as Unicode
    $Content | Set-Content -Path $GptTmplPath -Encoding Unicode

    # Increment Version
    $IniContent = Get-Content -Path $GptIniPath
    $NewIniContent = $IniContent | ForEach-Object {
        if ($_ -match "Version=(\d+)") {
            $CurrentVer = [int]$matches[1]
            "Version=$($CurrentVer + 1)"
        } else {
            $_
        }
    }
    Set-Content -Path $GptIniPath -Value $NewIniContent -Encoding ASCII

    # Refresh
    gpupdate /force
    
    # Cleanup Task
    Unregister-ScheduledTask -TaskName "PostPromoteFix" -Confirm:$false
    Stop-Transcript
'@
    $PostScriptContent | Out-File -Encoding ASCII "C:\PostPromote.ps1"

    # Register Scheduled Task to run at startup

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File C:\PostPromote.ps1"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "PostPromoteFix"

    # 5. Install AD DS & Promote
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    
    Write-Output "Promoting to Domain Controller..."
    $securePass = ConvertTo-SecureString $adminPass -AsPlainText -Force
    Install-ADDSForest -DomainName "${var.domain_name}" -SafeModeAdministratorPassword $securePass -Force
    
    Stop-Transcript
    Restart-Computer -Force
    </powershell>
  EOF

  tags = {
    Name = "ldapserver"
  }
}

resource "aws_eip_association" "eip_assoc" {
  instance_id   = aws_instance.windows_server.id
  allocation_id = aws_eip.server_ip.id
}

resource "aws_security_group" "windows_server" {
  name        = "windows-server-sg"
  description = "Security group for Windows Server"

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.ip_check.response_body)}/32"]
  }

  ingress {
    from_port   = 389
    to_port     = 389
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.ip_check.response_body)}/32"]
  }

  ingress {
    from_port   = 636
    to_port     = 636
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.ip_check.response_body)}/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

output "Deployment_Status" {
  value = <<-EOF
    ================================================================
    DEPLOYMENT STARTED SUCCESSFULLY
    ================================================================
    Server IP:     ${aws_eip.server_ip.public_ip}
    Domain:        ${var.domain_name}
    Subnet CIDR:   ${local.random_cidr}
    Username:      Administrator
    Password:      ${nonsensitive(local.final_password)}
    CA Cert:       Saved to 'ca.pem'
    
    PLEASE WAIT ~10-15 MINUTES FOR INSTALLATION TO COMPLETE.

    --- CONNECTION COMMANDS ---

    1. STRICT VALIDATION (Use CA File):
    LDAPTLS_CA_CERT=ca.pem ldapsearch \
      -vvv -x \
      -H ldaps://${aws_eip.server_ip.public_ip}:636 \
      -D "cn=Administrator,cn=Users,${local.dc_formatted}" \
      -w "${nonsensitive(local.final_password)}" \
      -b "${local.dc_formatted}" \
      -s sub

    2. INSECURE VALIDATION (Ignore CA):
    LDAPTLS_REQCERT=never ldapsearch \
      -vvv -x \
      -H ldaps://${aws_eip.server_ip.public_ip}:636 \
      -D "cn=Administrator,cn=Users,${local.dc_formatted}" \
      -w "${nonsensitive(local.final_password)}" \
      -b "${local.dc_formatted}" \
      -s sub

    3. MACOS FIX (Import CA to System Keychain):
    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.pem
    ================================================================
  EOF
}