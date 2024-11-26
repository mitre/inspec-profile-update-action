control 'SV-234059' do
  title 'Tanium must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Review the configured Sources.

If no "Sources" exist to send audit logs from the Tanium SQL Server to a SIEM tool, this is a finding.

Work with the SIEM administrator to determine if an alert is configured when audit data is no longer received as expected.

If there is no alert configured, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Connect".

Configure "Sources" to send audit logs from the Tanium SQL Server to a SIEM tool.

Work with the SIEM administrator to configure an alert when no audit data is received from Tanium based on the defined schedule of connections.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37244r610677_chk'
  tag severity: 'medium'
  tag gid: 'V-234059'
  tag rid: 'SV-234059r612749_rule'
  tag stig_id: 'TANS-CN-000016'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-37209r610678_fix'
  tag 'documentable'
  tag legacy: ['SV-102191', 'V-92089']
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
