control 'SV-77345' do
  title 'Riverbed Optimization System (RiOS) must enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level in accordance with applicable policy for the device.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Network devices use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the network device to control access between administrators (or processes acting on behalf of administrators) and objects (e.g., device commands, files, records, processes) in the network device.'
  desc 'check', 'Verify that RiOS is configured to the assigned privilege level for each administrator.

Navigate to the device CLI
Type: show rbm users

Verify that the privilege level is correct for each administrator

-- or --

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Verify that the privilege level is correct for each administrator

If the privilege level settings are not in accordance with applicable policy, this is a finding.'
  desc 'fix', %q(Configure RiOS to enforce assigned privilege level for each administrator.

Navigate to the device CLI
Type: rbm user <username> role <role> permissions <permissions>

Set the value of username, role, and permissions according to the privilege level of the applicable policy

Type: write memory
to save the current configuration settings to memory

-- or --

Navigate to the device Management Console
Navigate to Configure >> Security >> User Permissions

Set the values of 'Roles and Permissions' according to the privilege level in accordance with applicable policy

Click "Apply" to save the changes
Navigate to the top of the web page and click "Save" to write changes to memory)
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63649r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62855'
  tag rid: 'SV-77345r1_rule'
  tag stig_id: 'RICX-DM-000017'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-68773r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
