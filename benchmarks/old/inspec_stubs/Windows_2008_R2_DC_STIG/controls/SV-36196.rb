control 'SV-36196' do
  title 'Active directory user accounts, including administrators, must be configured to require the use of a Common Access Card (CAC), PIV-compliant hardware token, or Alternate Logon Token (ALT) for user authentication.'
  desc 'Smart cards such as the Common Access Card (CAC) support a two-factor authentication technique.  This provides a higher level of trust in the asserted identity than use of the username and password for authentication.'
  desc 'check', 'Verify active directory user accounts, including administrators, have "Smart card is required for interactive logon" selected.

Run "Active Directory Module for Windows PowerShell".
Enter the following:
"Get-ADUser -Filter {(Enabled -eq $True) -and (SmartcardLogonRequired -eq $False)} | FT Name"
 ("DistinguishedName" may be substituted for "Name" for more detailed output.)
If any user accounts are listed, this is a finding.

Alternately:
To view sample accounts in "Active Directory Users and Computers" (Available from various menus or run "dsa.msc"):
Select the Organizational Unit (OU) where the User accounts are located.  (By default this is the Users node; however, accounts may be under other organization-defined OUs.)
Right click the sample User account and select "Properties".
Select the "Account" tab.
If any User accounts do not have "Smart card is required for interactive logon" checked in the "Account Options" area, this is a finding.'
  desc 'fix', 'Configure all user accounts, including administrator accounts, in Active Directory to enable the option "Smart card is required for interactive logon".

Run "Active Directory Users and Computers" (Available from various menus or run "dsa.msc"):
Select the Organizational Unit (OU) where the user accounts are located.  (By default this is the Users node; however, accounts may be under other organization-defined OUs.)
Right click the user account and select "Properties".
Select the "Account" tab.
Check "Smart card is required for interactive logon" in the "Account Options" area.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-66221r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15488'
  tag rid: 'SV-36196r3_rule'
  tag stig_id: 'AD.1033_2008_R2'
  tag gtitle: 'PKI Authentication Req'
  tag fix_id: 'F-71585r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000765', 'CCI-000766', 'CCI-000767', 'CCI-000768', 'CCI-001948']
  tag nist: ['IA-2 (1)', 'IA-2 (2)', 'IA-2 (3)', 'IA-2 (4)', 'IA-2 (11)']
end
