control 'SV-246927' do
  title 'ONTAP must enforce administrator privileges based on their defined roles.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Network devices use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the network device to control access between administrators (or processes acting on behalf of administrators) and objects (e.g., device commands, files, records, processes) in the network device.'
  desc 'check', 'Use "security login show" to see all configured users and their roles. Use "security login role show" to see specific commands allowed for each role.

If ONTAP does not enforce administrator privileges based on their defined roles, this is a finding.'
  desc 'fix', 'Configure roles with "security login role create -role <name>" to create new roles, and "security login create -user-or-group-name <user_name> -role <name>" to assign the role to a specific user or group.'
  impact 0.7
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50359r769111_chk'
  tag severity: 'high'
  tag gid: 'V-246927'
  tag rid: 'SV-246927r769113_rule'
  tag stig_id: 'NAOT-AC-000006'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-50313r769112_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
