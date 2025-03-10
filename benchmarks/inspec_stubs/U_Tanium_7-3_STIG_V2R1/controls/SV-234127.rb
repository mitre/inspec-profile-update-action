control 'SV-234127' do
  title 'The Tanium application must set an inactive timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the web server can make certain that sessions that are not closed through the user logging out of an application are eventually closed.

Acceptable values are 5 minutes for high-value applications, 10 minutes for medium-value applications, and 20 minutes for low-value applications.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console. 

Click on "Administration".

Select the "Global Settings" tab.

In the "Show Settings Containing:" search box, type "max_console_idle_seconds".

Click "Enter".

If no results are returned, this is a finding.

If results are returned for "max_console_idle_seconds", but the value is not "900" or less, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Global Settings" tab.

Click on "New Setting".

In "New System Setting" dialog box, enter "max_console_idle_seconds" for "Setting Name:".

Enter "900" for "Setting Value:".

Select "Server" from the "Affects" drop-down list.

Select "Numeric" from the "Value Type" drop-down list.

Click "Save".

If "max_console_idle_seconds" exists but is not "900" or less, select the box beside the value and click "Edit".

Enter "900" or less for "Setting Value:".

Click "Save".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37312r610881_chk'
  tag severity: 'medium'
  tag gid: 'V-234127'
  tag rid: 'SV-234127r612749_rule'
  tag stig_id: 'TANS-SV-000067'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-37277r610882_fix'
  tag 'documentable'
  tag legacy: ['SV-102327', 'V-92225']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
