control 'SV-233257' do
  title 'The container platform must generate audit records when successful/unsuccessful attempts to modify security levels occur.'
  desc 'Unauthorized users could modify the security levels to exploit vulnerabilities within the container platform component. All the components must use the same standard so that the events can be tied together to understand what took place within the overall container platform. This must establish, correlate, and help assist with investigating the events relating to an incident, or identify those responsible.

Without audit record generation, unauthorized users can modify security levels unknowingly for malicious intent creating vulnerabilities within the container platform.'
  desc 'check', 'Review the container platform configuration to verify audit records are generated on successful/unsuccessful attempts to modify security levels. 

If audit records are not generated, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit records when successful/unsuccessful attempts to modify security levels.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36193r599407_chk'
  tag severity: 'medium'
  tag gid: 'V-233257'
  tag rid: 'SV-233257r599509_rule'
  tag stig_id: 'SRG-APP-000497-CTR-001245'
  tag gtitle: 'SRG-APP-000497'
  tag fix_id: 'F-36161r599408_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
