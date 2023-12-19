control 'SV-252847' do
  title 'Rancher MCM must never automatically remove or disable emergency accounts.'
  desc 'Emergency accounts are administrator accounts that are established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are automatically disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.

Emergency accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon/access is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency account is normally a different account that is created for use by vendors or system maintainers.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.

Local Admin user should exist so that Rancher can be used if the external authentication service encounters issues.'
  desc 'check', 'Ensure local emergency admin account has not been removed and is the only Local account. 

Navigate to the Triple Bar Symbol(Global) >> Users & Authentication. In the left navigation menu, click "Users".

There should be only one local account and that account should have administrator role.

If no local administrator account exists or there is more than one local account, this is a finding.'
  desc 'fix', 'Ensure local emergency admin account has not been removed and is the only Local account. 

Navigate to the Triple Bar Symbol(Global) >> Users & Authentication. In the left navigation menu, click "Users".

To Create a User:
-Click "Create".
-Complete the "Add User" form. Ensure Global Permissions are set to "Administrator".
-Click "Create".

To Delete a User:
-Select the user and click "Delete".'
  impact 0.5
  ref 'DPMS Target Rancher Government Solutions Multi-Cluster Manager'
  tag check_id: 'C-56303r819989_chk'
  tag severity: 'medium'
  tag gid: 'V-252847'
  tag rid: 'SV-252847r879644_rule'
  tag stig_id: 'CNTR-RM-000850'
  tag gtitle: 'SRG-APP-000234-CTR-000590'
  tag fix_id: 'F-56253r819990_fix'
  tag 'documentable'
  tag cci: ['CCI-001682']
  tag nist: ['AC-2 (2)']
end
