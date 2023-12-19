control 'SV-68685' do
  title 'The ALG must send an alert to, at a minimum, the ISSO and SCA when an audit processing failure occurs.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. Possible audit processing failures also include the inability of ALG to write to the central audit log.

This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations, (i.e., all audit data storage repositories combined), or both.

This does not apply to audit logs generated on behalf of the device itself (management).'
  desc 'check', 'Verify the ALG sends an alert to, at a minimum, the ISSO and SCA when an audit processing failure occurs.

If the ALG does not send an alert to, at a minimum, the ISSO and SCA when an audit processing failure occurs, this is a finding.'
  desc 'fix', 'Configure the ALG to send an alert to, at a minimum, the ISSO and SCA when an audit processing failure occurs.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55055r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54439'
  tag rid: 'SV-68685r1_rule'
  tag stig_id: 'SRG-NET-000088-ALG-000054'
  tag gtitle: 'SRG-NET-000088-ALG-000054'
  tag fix_id: 'F-59293r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
