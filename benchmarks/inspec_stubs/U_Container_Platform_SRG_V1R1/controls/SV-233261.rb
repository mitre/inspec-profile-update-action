control 'SV-233261' do
  title 'The container platform must generate audit records when successful/unsuccessful attempts to delete security objects occur.'
  desc 'Unauthorized users modify level the security levels to exploit vulnerabilities within the container platform component. All the components must use the same standard so that the events can be tied together to understand what took place within the overall container platform. This must establish, correlate, and help assist with investigating the events relating to an incident, or identify those responsible.

Without audit record generation, unauthorized users can access delete security objects unknowingly for malicious intent creating vulnerabilities within the container platform.'
  desc 'check', 'Review the container platform configuration to determine if audit records are generated on successful/unsuccessful attempts to delete security objects occur. 

If audit records are not generated, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit records on successful/unsuccessful attempts to delete security objects occur.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36197r599419_chk'
  tag severity: 'medium'
  tag gid: 'V-233261'
  tag rid: 'SV-233261r599509_rule'
  tag stig_id: 'SRG-APP-000501-CTR-001265'
  tag gtitle: 'SRG-APP-000501'
  tag fix_id: 'F-36165r599420_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
