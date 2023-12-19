control 'SV-233252' do
  title 'The container platform must generate audit records when successful/unsuccessful attempts to access security objects occur.'
  desc 'The container platform and its components must generate audit records when successful and unsuccessful access security objects occur. All the components must use the same standard so that the events can be tied together to understand what took place within the overall container platform. This must establish, correlate, and help assist with investigating the events relating to an incident, or identify those responsible.

Without audit record generation access controls levels can access by unauthorized users unknowingly for malicious intent creating vulnerabilities within the container platform.'
  desc 'check', 'Review the container platform configuration to verify audit records are generated on successful/unsuccessful attempts to access security objects. 

If audit records are not generated, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit records when successful/unsuccessful attempts to access security objects occur.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36188r601243_chk'
  tag severity: 'medium'
  tag gid: 'V-233252'
  tag rid: 'SV-233252r879863_rule'
  tag stig_id: 'SRG-APP-000492-CTR-001220'
  tag gtitle: 'SRG-APP-000492'
  tag fix_id: 'F-36156r601244_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
