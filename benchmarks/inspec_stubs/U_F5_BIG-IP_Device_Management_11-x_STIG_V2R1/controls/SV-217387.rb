control 'SV-217387' do
  title 'The BIG-IP appliance must be configured to enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level in accordance with applicable policy for the device.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Network devices use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the network device to control access between administrators (or processes acting on behalf of administrators) and objects (e.g., device commands, files, records, processes) in the network device.'
  desc 'check', 'Verify the BIG-IP appliance is configured to enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level in accordance with applicable policy for the device. 

Verify the BIG-IP appliance is configured to utilize a properly configured authentication server. 

Navigate to the BIG-IP System manager >> System >> Users >> Authentication.

Verify "Authentication: User Directory" is configured to use an approved remote authentication server that enforces the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level.

If the BIG-IP appliance is not configured to enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level in accordance with applicable policy for the device.'
  impact 0.7
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-18612r290715_chk'
  tag severity: 'high'
  tag gid: 'V-217387'
  tag rid: 'SV-217387r557520_rule'
  tag stig_id: 'F5BI-DM-000027'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-18610r290716_fix'
  tag 'documentable'
  tag legacy: ['SV-74541', 'V-60111']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
