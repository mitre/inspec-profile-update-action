control 'SV-81535' do
  title 'The Tanium Action Approval feature must be enabled for two person integrity when deploying actions to endpoints.'
  desc 'The Tanium Action Approval feature provides a "four eyes" control mechanism designed to achieve a high level of security and reduce the possibility of error for critical operations.

When this feature is enabled, an action configured by one Tanium console user will require a second Tanium console user with a role of Action Approver to approve the Action before it is deployed to targeted computers.

While this system slows workflow, the reliability of actions deployed will be greater on the Packaging and Targeting.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Global Settings" tab. 

In the search box beside "Show Settings Containing:" type "require_action_approval". Enter.

If no results are returned, this is a finding.

If results are returned for "require_action_approval", but the value is not "1", this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Global Settings" tab.

Click on "+ Add New Setting".

In "Create New Setting" dialog box, enter "require_action_approval" for "Setting Name:".

Enter "1" for "Setting Value:".

Select "Numeric" from "Value Type" drop-down list.

Select "Server" from "Affects drop-down list.

Click “Save”.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67681r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67045'
  tag rid: 'SV-81535r1_rule'
  tag stig_id: 'TANS-SV-000006'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-73145r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
