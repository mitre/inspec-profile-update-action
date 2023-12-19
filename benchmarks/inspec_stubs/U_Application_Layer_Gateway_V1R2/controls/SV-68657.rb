control 'SV-68657' do
  title 'The ALG providing user access control intermediary services must generate audit records when successful/unsuccessful attempts to delete privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

This requirement applies to the ALG traffic management functions such as content filtering or intermediary services. This does not apply to audit logs generated on behalf of the device (device management).'
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG generates audit records when successful/unsuccessful attempts to delete privileges occur.

If the ALG does not generate audit records when successful/unsuccessful attempts to delete privileges occur, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to generate audit records when successful/unsuccessful attempts to delete privileges occur.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55027r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54411'
  tag rid: 'SV-68657r1_rule'
  tag stig_id: 'SRG-NET-000499-ALG-000034'
  tag gtitle: 'SRG-NET-000499-ALG-000034'
  tag fix_id: 'F-59265r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
