control 'SV-233260' do
  title 'The container platform must generate audit records when successful/unsuccessful attempts to delete security levels occur.'
  desc 'The container platform and its components must generate audit records when deleting security levels. All the components must use the same standard so that the events can be tied together to understand what took place within the overall container platform. This must establish, correlate, and help assist with investigating the events relating to an incident, or identify those responsible.

Without audit record generation, unauthorized users can delete security levels unknowingly for malicious intent creating vulnerabilities within the container platform.'
  desc 'check', 'Review the container platform configuration to verify audit records are generated on successful/unsuccessful attempts to delete security levels. 

If audit records are not generated, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit records when successful/unsuccessful attempts to delete security levels.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36196r601267_chk'
  tag severity: 'medium'
  tag gid: 'V-233260'
  tag rid: 'SV-233260r601269_rule'
  tag stig_id: 'SRG-APP-000500-CTR-001260'
  tag gtitle: 'SRG-APP-000500'
  tag fix_id: 'F-36164r601268_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
