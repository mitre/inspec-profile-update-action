control 'SV-251404' do
  title 'The Ivanti MobileIron Core server must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both. 

'
  desc 'check', 'Verify Core is configured to alert the ISSO and SA in the event of an audit processing failure:

In the Core console, go to Logs >> Event Settings >> Add New System Event.

Verify System Storage Threshold has been reached is checked.

If System Storage Threshold has been reached is not checked, this is a finding.'
  desc 'fix', 'Configure Core to alert the ISSO and SA in the event of an audit processing failure:

Logs >> Event Settings >> Add New System Event >> ensure System Storage Threshold has been reached is checked.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54839r806342_chk'
  tag severity: 'medium'
  tag gid: 'V-251404'
  tag rid: 'SV-251404r806344_rule'
  tag stig_id: 'IMIC-11-003000'
  tag gtitle: 'SRG-APP-000108-UEM-000062'
  tag fix_id: 'F-54792r806343_fix'
  tag satisfies: ['FAU_ALT_EXT.1.1 \nReference: PP-MDM-412059']
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
