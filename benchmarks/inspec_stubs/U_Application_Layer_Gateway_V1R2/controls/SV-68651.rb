control 'SV-68651' do
  title 'The ALG must generate audit records when successful/unsuccessful attempts to modify security objects occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). Security objects are data objects which are controlled by security policy and bound to security attributes.

This requirement applies to the ALG traffic management functions such as content filtering or intermediary services. This does not apply to audit logs generated on behalf of the device (device management).'
  desc 'check', 'Verify the ALG generates audit records when successful/unsuccessful attempts to modify security objects occur.

If the ALG does not generate audit records when successful/unsuccessful attempts to modify security objects occur, this is a finding.'
  desc 'fix', 'Configure the ALG to generate audit records when successful/unsuccessful attempts to modify security objects occur.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55021r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54405'
  tag rid: 'SV-68651r1_rule'
  tag stig_id: 'SRG-NET-000496-ALG-000031'
  tag gtitle: 'SRG-NET-000496-ALG-000031'
  tag fix_id: 'F-59259r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
