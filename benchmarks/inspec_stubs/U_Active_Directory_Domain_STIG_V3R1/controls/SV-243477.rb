control 'SV-243477' do
  title 'User accounts with domain level administrative privileges must be members of the Protected Users group in domains with a domain functional level of Windows 2012 R2 or higher.'
  desc 'User accounts with domain level administrative privileges are highly prized in Pass-the-Hash/credential theft attacks.  The Protected Users group provides extra protections to accounts such as preventing authentication using NTLM.

These accounts include Enterprise and Domain Admins as well as other accounts that may have domain level privileges.

The Protected Users group requires a domain functional level of at least Windows 2012 R2 to provide domain level protections.'
  desc 'check', 'If the domain functional level is not at least Windows 2012 R2, this is NA.

Open "Windows PowerShell".

Enter "Get-ADDomain | FL DomainMode" to determine the domain functional level.

Open "Active Directory Users and Computers" (available from various menus or run "dsa.msc"). 

Compare membership of the Protected Users group to membership of the following groups. By default, the groups are under the node referenced; however, it is possible to move those under "Users" to another location.
Enterprise Admins (Users node)
Domain Admins (Users node)
Schema Admins (Users node)
Administrators (Builtin node)
Account Operators (Builtin node)
Backup Operators (Builtin node)

It is recommended that one account be excluded to ensure availability if there are issues with Kerberos.

Excluding the account left out for availability, if all user accounts from the local domain that are members of the domain level groups above are not also members of the Protected Users group, this is a finding. (User accounts is referring to accounts for personnel, not service accounts.)'
  desc 'fix', 'Add user accounts from the local domain that are members of the domain level administrative groups listed below to the Protected Users group. One account may excluded to ensure availability if there are issues with Kerberos.

Enterprise Admins (Users node)
Domain Admins (Users node)
Schema Admins (Users node)
Administrators (Builtin node)
Account Operators (Builtin node)
Backup Operators (Builtin node)

The use of the Protected Users group should be thoroughly tested before fully implementing.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46752r723464_chk'
  tag severity: 'medium'
  tag gid: 'V-243477'
  tag rid: 'SV-243477r723466_rule'
  tag stig_id: 'AD.0017'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46709r723465_fix'
  tag 'documentable'
  tag legacy: ['V-78131', 'SV-92837']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
