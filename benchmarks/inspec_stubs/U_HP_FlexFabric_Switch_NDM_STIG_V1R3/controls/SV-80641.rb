control 'SV-80641' do
  title 'The HP FlexFabric Switch must enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level in accordance with applicable policy for the device.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Network devices use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the HP FlexFabric Switch to control access between administrators (or processes acting on behalf of administrators) and objects (e.g., device commands, files, records, processes) in the HP FlexFabric Switch.'
  desc 'check', 'Determine if the HP FlexFabric Switch is configured to enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level in accordance with applicable policy for the switch. 

[HP] display local-user

Device management user admin:
 State:                    Active
 Service type:             SSH/Telnet/Terminal
 User group:               system
 Bind attributes:
 Authorization attributes:
  Work directory:          flash:
  User role list:          network-admin

 Password control configurations:

If the HP FlexFabric Switch does not enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level in accordance with applicable policy for the switch.

[HP] local-user admin
[HP-luser-manage-admin]
[HP-luser-manage-admin]authorization-attribute user-role network-admin'
  impact 0.7
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66797r1_chk'
  tag severity: 'high'
  tag gid: 'V-66151'
  tag rid: 'SV-80641r1_rule'
  tag stig_id: 'HFFS-ND-000013'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-72227r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
