control 'SV-233268' do
  title 'Direct access to the container platform must generate audit records.'
  desc 'Direct access to the container platform and its components must generate audit records. All the components must use the same standard so that the events can be tied together to understand what took place within the overall container platform. This must establish, correlate, and help assist with investigating the events relating to an incident, or identify those responsible.'
  desc 'check', 'Review the container platform configuration to determine if direct access of the container platform generates audit records. 

If audit records are not generated, this is a finding.'
  desc 'fix', 'Configure the container platform to generate audit records when accessed directly.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36204r601291_chk'
  tag severity: 'medium'
  tag gid: 'V-233268'
  tag rid: 'SV-233268r879879_rule'
  tag stig_id: 'SRG-APP-000508-CTR-001300'
  tag gtitle: 'SRG-APP-000508'
  tag fix_id: 'F-36172r601292_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
