control 'SV-81469' do
  title 'Control of the Tanium Client service must be restricted to SYSTEM access only for all managed clients.'
  desc "The reliability of the Tanium client's ability to operate depends upon controlling access to the Tanium client service. By restricting access to SYSTEM access only, the non-Tanium system administrator will not have the ability to impact operability of the service."
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

From the Dashboard, under "Client Service Hardening", click on "Control Service State Permissions".

The results will show a "Count" of clients matching the "Service Control is set to default permissions" query.

If the "Count" shows any quantity other than zero, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

From the Dashboard, under "Client Service Hardening", click on "Control Service State Permissions".
 
The results will show a "Count" of clients matching the "Service Control is set to default permissions" query.

Select the result line for "Service Control is set to default permissions".

Right-click on the number under "Count".

Choose "Deploy Action...".

The "Deploy Action" dialog box will display "Client Service Hardening - Set Service Permissions to Defaults" as the package.  -> Client Service Hardening - Set SYSTEM only permissions on Tanium Client directory.

The computer names comprising the "Count" of non-compliant systems will be displayed in the bottom.

Click on "Target & Schedule".

Configure the schedule for the requested action depending upon internal organizational procedures and policies for maintenance.

Click on "Finish".

Verify settings are correct.

Click on the "Confirm..." button at the bottom of the screen which will respond with a dialog box "Your action has been scheduled. It can be viewed on the actions tab."'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67615r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66979'
  tag rid: 'SV-81469r1_rule'
  tag stig_id: 'TANS-CL-000005'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-73079r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
