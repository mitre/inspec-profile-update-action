control 'SV-252845' do
  title 'When allowed by the central authentication system, the default role assigned to a user must be User-Base.'
  desc 'Rancher MCM uses roles for authentication. It is necessary to ensure the proper roles and permissions are configured. The role used by default does not ensure least privilege. The default role needs to be changed to allow least privilege access.'
  desc 'check', 'Verify User-Base is the default assigned role:
-From the GUI, navigate to Triple Bar Symbol(Global) >> Users & Authentication >> Roles. 
-Click "Standard User".
-At the top right, click the three dots, and then choose "Edit Config".
-Under "New User Default", ensure "No" is selected. 
-Click "User-Base".
-At the top right, click the three dots, and then "Edit Config".
-Under "New User Default", ensure "Yes" is selected.

If "No" is not selected for Standard User, this is a finding. 

If "Yes" is not selected for User-Base, this is a finding.'
  desc 'fix', 'From the GUI, navigate to Triple Bar Symbol(Global) >> Users & Authentication >> Roles.
-Click "Standard User".
-At the top right, click the three dots, and then "Edit Config".
-Under "New User Default", select "No" and click "Save".
-Click "User-Base".
-At the top right, click the three dots, and then click "Edit Config".
-Under "New User Default", select "Yes", and then click "Save".'
  impact 0.5
  ref 'DPMS Target Rancher Government Solutions Multi-Cluster Manager'
  tag check_id: 'C-56301r822505_chk'
  tag severity: 'medium'
  tag gid: 'V-252845'
  tag rid: 'SV-252845r822506_rule'
  tag stig_id: 'CNTR-RM-000080'
  tag gtitle: 'SRG-APP-000028-CTR-000080'
  tag fix_id: 'F-56251r822506_fix'
  tag 'documentable'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
