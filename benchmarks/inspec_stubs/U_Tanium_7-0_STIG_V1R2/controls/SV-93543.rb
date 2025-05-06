control 'SV-93543' do
  title 'The Tanium soap_max_keep_alive setting must be explicitly enabled to limit the number of simultaneous sessions.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement may be met via the application or by using information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Administration".

Select the "Global Settings" tab.

In the "Show Settings Containing:" search box type "soap_max_keep_alive".

Click "Enter".

If no results are returned, this is a finding.

If results are returned for "soap_max_keep_alive", but the value is not the value defined in the system documentation, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console and then click on "Administration".

Select the "Global Settings" tab.

Click on "New Setting".

In "New System Setting" dialog box enter "soap_max_keep_alive" for "Setting Name:".

Work with a Tanium Technical Account Manager (TAM) for a proper value, and enter this for the "Setting Value:".

Select "Server" from "Affects" drop-down list.

Select "Numeric" from "Value Type" drop-down list.

Click "Save".

Add this setting to the system documentation for validation.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78423r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78837'
  tag rid: 'SV-93543r1_rule'
  tag stig_id: 'TANS-SV-000047'
  tag gtitle: 'SRG-APP-000001'
  tag fix_id: 'F-85587r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
