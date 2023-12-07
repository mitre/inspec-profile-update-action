control 'SV-33885' do
  title 'PKI certificates associated with user accounts must be issued by the DoD PKI or an approved External Certificate Authority (ECA).'
  desc 'A PKI implementation depends on the practices established by the Certificate Authority (CA) to ensure the implementation is secure.  Without proper practices, the certificates issued by a CA have limited value in authentication functions.'
  desc 'check', %q(Open a command prompt (CMD.exe).

Enter "DSQuery User - Name * | DSGet User -DN -UPN -Display"

DSQuery can be more focused by adding domain and/or organizational unit names such as "OU=[OU Name], DC=[Domain], DC=[Top Level Domain]"

Review the User Principal Name (UPN) of user accounts, including administrators. 

Exclude built-in accounts such as Administrator and Guest.

If the User Principal Name (UPN) is not in the format of an individual's identifier for the certificate type and for the appropriate domain suffix, this is a finding.

For standard NIPRNET certificates the individual's identifier is in the format of an Electronic Data Interchange - Personnel Identifier (EDI-PI).

Alt Tokens and other certificates may use a different UPN format than the EDI-PI, which vary by organization.  Verify these with the organization.

NIPRNET Example: 
dn - upn - display
CN=User1, CN=Users, DC=Test, DC=Mil - 1234567890@mil - User1

See PKE documentation for other network domain suffixes.

If the mappings are to certificates issued by a CA authorized by the Component's CIO, this is a CAT II finding.)
  desc 'fix', 'Map user accounts, including administrators, to PKI certificates using the appropriate User Principal Name (UPN) for the network. See PKE documentation for details.'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-75977r2_chk'
  tag severity: 'high'
  tag gid: 'V-26683'
  tag rid: 'SV-33885r4_rule'
  tag stig_id: 'DS00.2141_2008'
  tag gtitle: 'Directory PKI Certificate Source - Users'
  tag fix_id: 'F-80491r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
