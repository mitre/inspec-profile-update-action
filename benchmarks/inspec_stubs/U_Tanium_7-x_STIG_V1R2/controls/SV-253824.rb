control 'SV-253824' do
  title 'The Tanium application must alert the information system security officer and system administrator (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect".

4. Review the configured Connections under "Connections" section.

Work with the security information and event management (SIEM) administrator to determine if an alert is configured when audit data is no longer received as expected.

If no alert is configured, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect".

4. Expand the left menu.

5. Click "Connections".

6. Configure a Connection for the "Tanium Audit Source" source from the Tanium Application to a SIEM tool.

Work with the SIEM administrator to configure an alert when no audit data is received from Tanium based on the defined schedule of connections.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57276r842498_chk'
  tag severity: 'medium'
  tag gid: 'V-253824'
  tag rid: 'SV-253824r842500_rule'
  tag stig_id: 'TANS-CN-000016'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-57227r842499_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
