control 'SV-253841' do
  title 'The Tanium Action Approval feature must be enabled for two-person integrity when deploying actions to endpoints.'
  desc 'The Tanium Action Approval feature provides a two-person integrity control mechanism designed to achieve a high level of security and reduce the possibility of error for critical operations.

When this feature is enabled, an action configured by one Tanium console user will require a second Tanium console user with a role of Action Approver (or higher) to approve the action before it is deployed to targeted computers.

While this system slows workflow, the reliability of actions deployed will be greater on the Packaging and Targeting.

'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Administration" on the top navigation banner.

3. Under "Configuration", select "Platform Settings".

4. In the "Filter items" search box, type "require_action_approval".

5. Click "Enter".

If no results are returned, this is a finding.

If results are returned for "require_action_approval", but the value is not "1", this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication. 

2. Click "Administration" on the top navigation banner. 

3. Under "Configuration", select "Platform Settings". 

4. If "require_action_approval" does not exist: click "Create Setting". 

5. Select "Server" box for "Setting Type".

6. In "Create Platform Setting" dialog box, enter "require_action_approval" for "Name". 

7. Select "Numeric" radio button from "Value Type".

8. Select "Value" and enter "1". 

9. Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57293r842549_chk'
  tag severity: 'medium'
  tag gid: 'V-253841'
  tag rid: 'SV-253841r858414_rule'
  tag stig_id: 'TANS-SV-000006'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-57244r842550_fix'
  tag satisfies: ['SRG-APP-000488']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-002460']
  tag nist: ['AC-3', 'SC-18 (4)']
end
