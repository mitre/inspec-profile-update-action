control 'SV-69011' do
  title 'The ALG providing user access control intermediary services must generate audit records showing starting and ending time for user access to the system.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

This requirement applies to the ALG traffic management functions such as content filtering or intermediary services. This does not apply to audit logs generated on behalf of the device (device management).'
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG generates audit records showing starting and ending time for user access to the system.

If the ALG does not generate audit records showing starting and ending time for user access to the system, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to generate audit records showing starting and ending time for user access to the system.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55387r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54765'
  tag rid: 'SV-69011r1_rule'
  tag stig_id: 'SRG-NET-000505-ALG-000039'
  tag gtitle: 'SRG-NET-000505-ALG-000039'
  tag fix_id: 'F-59623r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
