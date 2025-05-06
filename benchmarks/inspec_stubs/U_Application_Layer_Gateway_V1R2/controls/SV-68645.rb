control 'SV-68645' do
  title 'The ALG that is part of a CDS must generate audit records when successful/unsuccessful attempts to access security levels occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). Access for different security levels maintains separation between resources (particularly stored data) of different security domains.

This requirement applies to the ALG traffic management functions such as content filtering or intermediary services. This does not apply to audit logs generated on behalf of the device (device management).'
  desc 'check', 'If the ALG is not part of the CDS, this is not applicable.

Verify the ALG generates audit records when successful/unsuccessful attempts to access security levels occur.

If the ALG does not generate audit records when successful/unsuccessful attempts to access security levels occur, this is a finding.'
  desc 'fix', 'If the ALG is part of the CDS, configure the ALG to generate audit records when successful/unsuccessful attempts to access security levels occur.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55015r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54399'
  tag rid: 'SV-68645r1_rule'
  tag stig_id: 'SRG-NET-000493-ALG-000028'
  tag gtitle: 'SRG-NET-000493-ALG-000028'
  tag fix_id: 'F-59253r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
