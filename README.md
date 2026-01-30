# Active Directory with LDAP
## What's this?
This Terraform project deploys a Windows server in AWS and automatically installs and configures Active Directory, LDAP, and LDAPS for use with HashiCorp Vault.

## What does it provide?
- LDAP connectivity on TCP port `389`
- LDAPS connectivity on TCP port `636`
- RDP connectivity on TCP port `3389`

**PLEASE NOTE:** 
- The default security group allows only the source IP of the system (public exit point) where the TF project was applied.
- The Default Domain Controllers Policy in AD has been altered to allow all users RDP access to the server.

## Prerequisites
- Terraform installed
- AWS Credentials (exported as environment variables or `credentials` file)

## Usage
### Check
- Create a `terraform.tfvars` and set the variables to match your environment.
```
aws_region ="us-east-1"
password = "" // Only set a value if you don't want a randomly generated password for the domain controller, otherwise the password set here will be used. Make sure it conforms to Microsoft Complexity Requirements.
domain_name = "adldap.lab"
instance_type = "t3.medium"
```

### Deploy
- `terraform apply`
- It takes around 10 - 15 minutes for the deployment to complete.
- Once complete, RDP connections to the EC2 instance is possible as well as sending LDAP and LDAPS queries.

### Destroy
`terraform destroy`




