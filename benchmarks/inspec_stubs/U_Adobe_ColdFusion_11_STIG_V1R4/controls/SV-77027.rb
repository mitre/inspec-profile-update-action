control 'SV-77027' do
  title 'ColdFusion must have ColdFusion component (CFC) type checking enabled.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry field and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

Invalid input can also occur within applications to ColdFusion components.  The parameters can be input from users that are not properly type checked or from data computed within the application.  When the data is not type checked, the receiving component may cause an error that is unhandled or throw an exception that puts the application server and/or hosted application into an unsecure posture.  To limit invalid calls, ColdFusion component (CFC) type checking must be disabled."
  desc 'check', 'Within the Administrator Console, navigate to the "Settings" page under the "Server Settings" menu.

If the "Disable CFC Type check" is checked, this is a finding.'
  desc 'fix', 'Navigate to the "Settings" page under the "Server Settings" menu.  Uncheck "Disable CFC Type check" and select the "Submit Changes" button.'
  impact 0.5
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-63341r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62537'
  tag rid: 'SV-77027r1_rule'
  tag stig_id: 'CF11-06-000223'
  tag gtitle: 'SRG-APP-000447-AS-000273'
  tag fix_id: 'F-68457r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
