control 'SV-95581' do
  title 'AAA Services must be configured to alert the SA and ISSO when any audit processing failure occurs.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected. 

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Verify AAA Services are configured to alert the SA and ISSO when any audit processing failure occurs.

If AAA Services are not configured to alert the SA and ISSO when any audit processing failure occurs, this is a finding.'
  desc 'fix', 'Configure AAA Services to alert the SA and ISSO when any audit processing failure occurs.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80607r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80871'
  tag rid: 'SV-95581r2_rule'
  tag stig_id: 'SRG-APP-000108-AAA-000290'
  tag gtitle: 'SRG-APP-000108-AAA-000290'
  tag fix_id: 'F-87725r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
