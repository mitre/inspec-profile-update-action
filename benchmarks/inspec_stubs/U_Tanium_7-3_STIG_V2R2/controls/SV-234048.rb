control 'SV-234048' do
  title 'The Tanium Application Server must be configured with a connector to sync to Microsoft Active Directory for account management functions.'
  desc 'By restricting access to the Tanium Server to only Microsoft Active Directory, user accounts and related permissions can be strictly monitored. Account management will be under the operational responsibility of the System Administrator for the Windows Operation System Active Directory.

'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console, then click on "Configuration".

Click the down arrow to view Apps.

Find "LDAP Sync".

Verify a sync exists under "Enabled Servers".

If no sync exists, this is a finding.

If sync exists under "Disabled Servers", this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console, then click on "Configuration".

Click the down arrow to view Apps.

Find "LDAP Sync".

Click "Add Server".

Complete the settings using guidance from https://docs.tanium.com/platform_user/platform_user/console_using_ldap.html.

Click "Show Preview to Continue".

Review the users and groups to be imported.

Save the configuration.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37233r610644_chk'
  tag severity: 'medium'
  tag gid: 'V-234048'
  tag rid: 'SV-234048r612749_rule'
  tag stig_id: 'TANS-CN-000002'
  tag gtitle: 'SRG-APP-000233'
  tag fix_id: 'F-37198r610645_fix'
  tag satisfies: ['SRG-APP-000233', 'SRG-APP-000317']
  tag 'documentable'
  tag legacy: ['SV-102169', 'V-92067']
  tag cci: ['CCI-001084', 'CCI-002142']
  tag nist: ['SC-3', 'AC-2 (10)']
end
