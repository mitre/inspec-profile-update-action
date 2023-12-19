control 'SV-243194' do
  title 'The network device must enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level in accordance with applicable policy for the device.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. 

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Network devices use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the network device to control access between administrators (or processes acting on behalf of administrators) and objects (e.g., device commands, files, records, processes) in the network device.'
  desc 'check', 'Review the accounts authorized for access to the network device. Determine if the accounts are assigned the lowest privilege level necessary to perform assigned duties. User accounts must be set to a specific privilege level, which can be mapped to specific commands or a group of commands. Authorized accounts should have the least privilege level unless deemed necessary for assigned duties.

If authorized accounts are assigned to greater privileges than necessary, this is a finding.'
  desc 'fix', 'Configure authorized accounts with the least privilege rule. Each user will have access to only the privileges they require to perform their assigned duties.'
  impact 0.7
  ref 'DPMS Target Network WLAN Controller Mgmt'
  tag check_id: 'C-46469r720035_chk'
  tag severity: 'high'
  tag gid: 'V-243194'
  tag rid: 'SV-243194r879530_rule'
  tag stig_id: 'WLAN-ND-000700'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-46426r720036_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
