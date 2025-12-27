control 'SV-214360' do
  title 'The Apache web server must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Work with the SIEM administrator to determine if an alert is configured when audit data is no longer received as expected.

If there is no alert configured, this is a finding.'
  desc 'fix', 'Work with the SIEM administrator to configure an alert when no audit data is received from Apache based on the defined schedule of connections.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15572r277583_chk'
  tag severity: 'medium'
  tag gid: 'V-214360'
  tag rid: 'SV-214360r505936_rule'
  tag stig_id: 'AS24-W1-000970'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-15570r277584_fix'
  tag 'documentable'
  tag legacy: ['SV-104685', 'V-94855']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
