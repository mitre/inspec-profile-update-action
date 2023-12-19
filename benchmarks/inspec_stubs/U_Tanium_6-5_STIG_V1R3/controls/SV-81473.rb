control 'SV-81473' do
  title 'The permissions on the Tanium Client directory must be restricted to only the SYSTEM account on all managed clients.'
  desc "By restricting access to the Tanium Client directory on managed clients, the Tanium client's ability to operate and function as designed will be protected from malicious attack and unintentional modifications by end users."
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

From the Dashboard, under "Client Service Hardening", click on "Control Service State Permissions".

The results will show a "Count" of clients with restricted and non-restricted permissions for "Tanium Client Service".

Non-compliant clients will have a count other than 0 for "Service Control is set to default permissions" or "Unknown Service Control Permissions.

If there is a "Count" other than "0" for "Service Control is set to default permissions" or "Unknown Service Control Permissions", this is a finding.'
  desc 'fix', %q(Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

From the Dashboard, under "Client Service Hardening", click on "Control Service State Permissions".

The results will show a "Count" of clients' compliant and non-compliant hardening for the "Tanium Client Service".

Non-compliant clients will have a count other than 0 for "Service Control is set to default permissions" or "Unknown Service Control Permissions.

Select each of the ""Service Control is set to default permissions" or "Unknown Service Control Permissions." statuses, right-click and select "Deploy Action...."

The "Deploy Action" dialog box will display "Client Service Hardening - Control Service State Permissions" as the package. The computer names comprising the "Count" of non-compliant systems will be displayed in the bottom.

Click on "Target & Schedule".

Configure the schedule for the requested action depending upon internal organizational procedures and policies for maintenance.

Click on "Finish".

Verify settings are correct. 

Click on the "Confirm..." button at the bottom of the screen which will respond with a dialog box "Your action has been scheduled. It can be viewed on the actions tab.")
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67619r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66983'
  tag rid: 'SV-81473r2_rule'
  tag stig_id: 'TANS-CL-000007'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-73083r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
