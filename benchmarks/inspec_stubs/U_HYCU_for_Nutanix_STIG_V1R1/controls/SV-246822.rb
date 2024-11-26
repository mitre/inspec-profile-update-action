control 'SV-246822' do
  title 'The HYCU 4.1 Application must enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level in accordance with applicable policy for the device.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Network devices use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'Review the Self-Service menu within HYCU to view accounts and user roles (Administrator, Backup Operator, Restore Operator, Backup and Restore Operator, or Viewer).

User roles have a predefined and non-changeable set of user privileges. To check exact set of privileges of each user, navigate to Self-Service context in the HYCU UI.

Click on the question mark in the upper-right corner, followed by "Help with This Page". Scroll down to the "User Roles" section.

If users can perform more functions than those specified for their role, this is a finding.'
  desc 'fix', 'Apply the appropriate user role to the required user from one of the predefined and non-changeable roles: Administrator, Backup Operator, Restore Operator, Backup and Restore Operator, or Viewer.'
  impact 0.7
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50254r768128_chk'
  tag severity: 'high'
  tag gid: 'V-246822'
  tag rid: 'SV-246822r768130_rule'
  tag stig_id: 'HYCU-AC-000004'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-50208r768129_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
