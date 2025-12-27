control 'SV-234082' do
  title 'The Tanium Action Approval feature must be enabled for two-person integrity when deploying actions to endpoints.'
  desc 'The Tanium Action Approval feature provides a "four eyes" control mechanism designed to achieve a high-level of security and reduce the possibility of error for critical operations.

When this feature is enabled, an action configured by one Tanium console user will require a second Tanium console user with a role of Action Approver (or higher) to approve the action before it is deployed to targeted computers.

While this system slows workflow, the reliability of actions deployed will be greater on the Packaging and Targeting.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console then click on "Administration".

Select the "Global Settings" tab.

In the "Show Settings Containing:" search box type "require_action_approval".

Click “Enter”.

If no results are returned, this is a finding.

If results are returned for "require_action_approval", but the value is not "1", this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console then click on "Administration".

Select the "Global Settings" tab.

If "require_action_approval" does not exist: click on "New Setting".

In "New System Setting" dialog box, enter "require_action_approval" for "Setting Name:".

Enter "1" for "Setting Value:".

Select "Server" from "Affects" drop-down list.

Select "Numeric" from "Value Type" drop-down list.

Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37267r610746_chk'
  tag severity: 'medium'
  tag gid: 'V-234082'
  tag rid: 'SV-234082r612749_rule'
  tag stig_id: 'TANS-SV-000006'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-37232r610747_fix'
  tag 'documentable'
  tag legacy: ['SV-102237', 'V-92135']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
