control 'SV-254898' do
  title 'The Tanium application must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect".

4. Review the configured Connections under "Connections" section.

Work with the SIEM administrator to determine if an alert is configured when audit data is no longer received as expected.

If there is no alert configured, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with multi-factor authentication. 

2. Click "Modules" on the top navigation banner. 

3. Click "Connect".

4. Expand the left menu.

5. Click "Connections".

6. Configure a Connection for the "Tanium Audit Source" source from the Tanium Application to a SIEM tool.

Work with the SIEM administrator to configure an alert when no audit data is received from Tanium based on the defined schedule of connections.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58511r867592_chk'
  tag severity: 'medium'
  tag gid: 'V-254898'
  tag rid: 'SV-254898r867594_rule'
  tag stig_id: 'TANS-AP-000260'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-58455r867593_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
