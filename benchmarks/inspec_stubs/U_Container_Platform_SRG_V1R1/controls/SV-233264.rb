control 'SV-233264' do
  title 'The container platform must generate audit record for privileged activities.'
  desc 'The container platform components will generate audit records for privilege activities and container platform runtime, registry, and keystore must generate access audit records to detect possible malicious intent. All the components must use the same standard so that the events can be tied together to understand what took place within the overall container platform. It would be difficult to establish, correlate, and investigate events relating to an incident or identify those responsible without these activities. Audit records can be generated from various components within the container platform.'
  desc 'check', 'Review the documentation and configuration guides to determine if the container platform generates log records for privileged activities. 

If log records are not generated for privileged activities, this is a finding.'
  desc 'fix', 'Configure the container platform to generate log records for privileged activities.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36200r599428_chk'
  tag severity: 'medium'
  tag gid: 'V-233264'
  tag rid: 'SV-233264r599509_rule'
  tag stig_id: 'SRG-APP-000504-CTR-001280'
  tag gtitle: 'SRG-APP-000504'
  tag fix_id: 'F-36168r599429_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
