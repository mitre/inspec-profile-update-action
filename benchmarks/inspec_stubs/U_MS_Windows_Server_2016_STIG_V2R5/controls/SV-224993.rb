control 'SV-224993' do
  title 'PKI certificates associated with user accounts must be issued by the DoD PKI or an approved External Certificate Authority (ECA).'
  desc 'A PKI implementation depends on the practices established by the Certificate Authority (CA) to ensure the implementation is secure. Without proper practices, the certificates issued by a CA have limited value in authentication functions.'
  desc 'check', %q(This applies to domain controllers. It is NA for other systems.

Review user account mappings to PKI certificates.

Open "Windows PowerShell".

Enter "Get-ADUser -Filter * | FT Name, UserPrincipalName, Enabled".

Exclude disabled accounts (e.g., DefaultAccount, Guest) and the krbtgt account.

If the User Principal Name (UPN) is not in the format of an individual's identifier for the certificate type and for the appropriate domain suffix, this is a finding.

For standard NIPRNet certificates the individual's identifier is in the format of an Electronic Data Interchange - Personnel Identifier (EDI-PI).

Alt Tokens and other certificates may use a different UPN format than the EDI-PI which vary by organization. Verified these with the organization.

NIPRNet Example:
Name - User Principal Name
User1 - 1234567890@mil

See PKE documentation for other network domain suffixes.

If the mappings are to certificates issued by a CA authorized by the Component's CIO, this is a CAT II finding.)
  desc 'fix', 'Map user accounts to PKI certificates using the appropriate User Principal Name (UPN) for the network. See PKE documentation for details.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26684r465881_chk'
  tag severity: 'high'
  tag gid: 'V-224993'
  tag rid: 'SV-224993r569186_rule'
  tag stig_id: 'WN16-DC-000300'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-26672r465882_fix'
  tag 'documentable'
  tag legacy: ['V-73615', 'SV-88279']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
