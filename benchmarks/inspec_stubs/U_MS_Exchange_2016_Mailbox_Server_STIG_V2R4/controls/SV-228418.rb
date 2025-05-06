control 'SV-228418' do
  title 'Exchange must have authenticated access set to Integrated Windows Authentication only.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 

This requirement is applicable to access control enforcement applications (e.g., authentication servers) and other applications that perform information and system access control functions.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-OwaVirtualDirectory | Select ServerName, Name, Identity,*Authentication
 
If the value of "WindowsAuthentication" is not set to "True", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-OwaVirtualDirectory -Identity '<IdentityName>' -WindowsAuthentication $true

Note: The <IdentityName> value must be in single quotes.

Example for the Identity Name: <ServerName>\\owa (Default website)"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30651r497050_chk'
  tag severity: 'medium'
  tag gid: 'V-228418'
  tag rid: 'SV-228418r612748_rule'
  tag stig_id: 'EX16-MB-002930'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-30636r497051_fix'
  tag 'documentable'
  tag legacy: ['SV-95427', 'V-80717']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
