control 'SV-233256' do
  title 'The container platform must generate audit records when successful/unsuccessful attempts to modify security objects occur.'
  desc 'The container platform and its components must generate audit records when modifying security objects. All the components must use the same standard so that the events can be tied together to understand what took place within the overall container platform. This must establish, correlate, and help assist with investigating the events relating to an incident, or identify those responsible.

Without audit record generation, unauthorized users can modify security objects unknowingly for malicious intent creating vulnerabilities within the container platform.'
  desc 'check', 'Review the container platform configuration to verify audit records are generated on successful/unsuccessful attempts to modify security objects. 

If audit records are not generated, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit records when successful/unsuccessful attempts to modify security objects.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36192r599404_chk'
  tag severity: 'medium'
  tag gid: 'V-233256'
  tag rid: 'SV-233256r599509_rule'
  tag stig_id: 'SRG-APP-000496-CTR-001240'
  tag gtitle: 'SRG-APP-000496'
  tag fix_id: 'F-36160r599405_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
