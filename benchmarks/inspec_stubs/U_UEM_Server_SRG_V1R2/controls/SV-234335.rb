control 'SV-234335' do
  title 'The UEM SRG must alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both. 

Satisfies:FAU_ALT_EXT.1.1 
Reference:PP-MDM-412059'
  desc 'check', 'Verify the UEM server alerts the ISSO and SA (at a minimum) in the event of an audit processing failure.

If the UEM server does not alert the ISSO and SA (at a minimum) in the event of an audit processing failure, this is a finding.'
  desc 'fix', 'Configure the UEM server to alert the ISSO and SA (at a minimum) in the event of an audit processing failure.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37520r614015_chk'
  tag severity: 'medium'
  tag gid: 'V-234335'
  tag rid: 'SV-234335r879570_rule'
  tag stig_id: 'SRG-APP-000108-UEM-000062'
  tag gtitle: 'SRG-APP-000108'
  tag fix_id: 'F-37485r614016_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
