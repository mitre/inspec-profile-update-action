control 'SV-233229' do
  title 'The container platform must implement organization-defined security safeguards to protect system CPU and memory from resource depletion and unauthorized code execution.'
  desc 'The execution of images within the container platform runtime must implement organizational defined security safeguards to prevent distributed denial-of-service (DDOS) and other possible attacks against the container image at runtime.

Security safeguards employed to protect memory and CPU include, for example, data execution prevention and address space layout randomization. Data execution prevention safeguards can be software-enforced. Other means of protection are to limit memory and CPU resources to a container.'
  desc 'check', 'Review the container platform configuration to determine if safeguards are in place to protect the system memory and CPU from resource depletion and unauthorized execution. 

If safeguards are not in place, this is a finding.'
  desc 'fix', 'Configure the container platform to have safeguards in place to protect the system memory and CPU from resource depletion and unauthorized code execution.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36165r601174_chk'
  tag severity: 'medium'
  tag gid: 'V-233229'
  tag rid: 'SV-233229r879821_rule'
  tag stig_id: 'SRG-APP-000450-CTR-001105'
  tag gtitle: 'SRG-APP-000450'
  tag fix_id: 'F-36133r601175_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
