control 'SV-226266' do
  title 'PKI certificates associated with user accounts must be issued by the DoD PKI or an approved External Certificate Authority (ECA).'
  desc 'A PKI implementation depends on the practices established by the Certificate Authority (CA) to ensure the implementation is secure.  Without proper practices, the certificates issued by a CA have limited value in authentication functions.'
  desc 'check', %q(Open "PowerShell" as Administrator.

Enter "Get-ADUser -Filter * | FT Name, UserPrincipalName, Enabled -AutoSize".

Review the User Principal Name (UPN) of user accounts, including administrators. 

Exclude the built-in accounts such as Administrator and Guest.

If the User Principal Name (UPN) is not in the format of an individual's identifier for the certificate type and for the appropriate domain suffix, this is a finding.

For standard NIPRNET certificates the individual's identifier is in the format of an Electronic Data Interchange - Personnel Identifier (EDI-PI).

Alt Tokens and other certificates may use a different UPN format than the EDI-PI, which vary by organization.  Verify these with the organization.

NIPRNET Example: 
Name - User Principal Name
User1 - 1234567890@mil

See PKE documentation for other network domain suffixes.

If the mappings are to certificates issued by a CA authorized by the Component's CIO, this is a CAT II finding.)
  desc 'fix', 'Map user accounts to PKI certificates using the appropriate User Principal Name (UPN) for the network. See PKE documentation for details.'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27968r476642_chk'
  tag severity: 'high'
  tag gid: 'V-226266'
  tag rid: 'SV-226266r794526_rule'
  tag stig_id: 'WN12-PK-000007-DC'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-27956r476643_fix'
  tag 'documentable'
  tag legacy: ['SV-51191', 'V-26683']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
