control 'SV-60171' do
  title 'The AirWatch MDM Server must implement separation of administrator duties by requiring a specific role be assigned to each administrator account.'
  desc 'Separation of duties supports the management of individual accountability and reduces the power of one individual or administrative account.  Employing a separation of duties model reduces the threat that one individual has the authority to make changes to a system, and the authority to delete any record of those changes. 
This requirement is intended to limit exposure due to operating from within a privileged account or role.  The inclusion of a role is intended to address those situations where an access control policy, such as Role Based Access Control (RBAC), is being implemented and where a change of role provides the same degree of assurance in the change of access authorizations for both the user and all processes acting on behalf of the user as would be provided by a change between a privileged and non-privileged account. 
It is recommended that the following or similar roles be supported:  
- AirWatch MDM Server administrative account administrator:  responsible for server installation, initial configuration, and maintenance functions.
- Security configuration policy administrator (IA technical professional):  responsible for security configuration of the server and setting up and maintenance of mobile device security policies.
- Device management administrator (Technical operator):  responsible for maintenance of mobile device accounts, including setup, change of account configurations, and account deletion.
- Auditor (internal auditor or reviewer):  responsible for reviewing and maintaining server and mobile device audit logs.'
  desc 'check', 'Review the AirWatch MDM Server configuration to ensure there are accounts associated with the following roles:  
 
- AirWatch MDM Server administrative account administrator:  responsible for server installation, initial configuration, and maintenance functions.
- Security configuration policy administrator (IA technical professional):  responsible for security configuration of the server and setting up and maintenance of mobile device security policies.
- Device management administrator (Technical operator):  responsible for maintenance of mobile device accounts, including setup, change of account configurations, and account deletion.
- Auditor (internal auditor or reviewer):  responsible for reviewing and maintaining server and mobile device audit logs.

If this separation of duties is not present, this is a finding.

Ensure custom AirWatch roles:  (1) click "Menu" from the console tool bar, (2) click "Administrators" under "Accounts" heading, (3) click "Roles" on left-hand tool bar, and (4) click on applicable role to check.  Note: only Roles created due to organizational necessity will be created by the Administrator and can be checked in this fashion; not all Roles may be used at every organizational site.'
  desc 'fix', 'Create and configure accounts to be aligned with the following roles:
 
- AirWatch MDM Server administrative account administrator:  responsible for server installation, initial configuration, and maintenance functions.
- Security configuration policy administrator (IA technical professional):  responsible for security configuration of the server and setting up and maintenance of mobile device security policies.
- Device management administrator (Technical operator):  responsible for maintenance of mobile device accounts, including setup, change of account configurations, and account deletion.
- Auditor (internal auditor or reviewer):  responsible for reviewing and maintaining server and mobile device audit logs.

Create custom AirWatch roles by clicking (1) "Menu" from the console tool bar, (2) selecting "Administrators" from under the "Accounts" heading from the drop-down menu, (3) click "Roles" on left-hand tool bar, and (4) click "Add Role" from the Roles page.  (5) Fill out applicable Roles information, and (6) click "Save".  (7) Click "Admin Accounts" on left-hand tool bar, and from "Administrators" screen, (8) click "Add User".  (9) Fill out applicable user information, (10) click Roles tab, and (11) assign previously created customer role to this account.  (12) Click "Save".'
  impact 0.7
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-50065r2_chk'
  tag severity: 'high'
  tag gid: 'V-47299'
  tag rid: 'SV-60171r1_rule'
  tag stig_id: 'ARWA-01-000005'
  tag gtitle: 'SRG-APP-062-MDM-003-SRV'
  tag fix_id: 'F-51005r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000037']
  tag nist: ['AC-5 c']
end
