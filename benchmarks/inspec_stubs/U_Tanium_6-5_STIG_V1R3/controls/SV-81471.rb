control 'SV-81471' do
  title 'The ability to uninstall the Tanium Client service must be disabled on all managed clients.'
  desc "By default, end users have the ability to uninstall software on their clients. In the event the Tanium Client software is uninstalled, the Tanium Server is unable to manage the client and must re-deploy to the client. Preventing the software from being displayed in the client's Add/Remove Programs will lessen the risk of the software being uninstalled by non-Tanium System Administrators."
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

From the Dashboard, under "Client Service Hardening", click on "Hide From Add-Remove Programs".

The results will show a "Count" of clients matching the "Tanium Client Visible in Add-Remove Programs" query.

If the "Count" shows any quantity other than zero, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

From the Dashboard, under "Client Service Hardening", click on "Hide From Add-Remove Programs".
 
The results will show a "Count" of clients matching the "Tanium Client Visible in Add-Remove Programs" query.

Select the result line.

Right-click on the number under "Count".

Choose "Deploy Action...".

The "Deploy Action" dialog box will display "Client Service Hardening - Hide Client from Add-Remove Programs" as the package. The computer names comprising the "Count" of non-compliant systems will be displayed in the bottom.

Click on "Target & Schedule".

Configure the schedule for the requested action depending upon internal organizational procedures and policies for maintenance.

Click on "Finish".

Verify settings are correct. 

Click on the "Confirm..." button at the bottom of the screen which will respond with a dialog box "Your action has been scheduled. It can be viewed on the actions tab."'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67617r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66981'
  tag rid: 'SV-81471r1_rule'
  tag stig_id: 'TANS-CL-000006'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-73081r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
