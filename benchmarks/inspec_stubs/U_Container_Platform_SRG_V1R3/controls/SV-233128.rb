control 'SV-233128' do
  title 'The container platform must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'The container platform makes host system resources available to container services. These shared resources, such as the host system kernel, network connections, and storage, must be protected to prevent unauthorized and unintended information transfer. The protections must be implemented for users and processes acting on behalf of users.'
  desc 'check', 'Review the container platform architecture documentation to find out if and how it protects the resources of one process or user (such as working memory, storage, host system kernel, network connections) from unauthorized access by another user or process. 

If the container platform configuration settings do not effectively implement these protections to prevent unauthorized access by another user or process, this is a finding.'
  desc 'fix', 'Deploy a container platform capable of effectively protecting the resources of one process or user from unauthorized access by another user or process. Configure the container platform to effectively protect the resources of one process or user from unauthorized access by another user or process. The container security solution should help the user understand where the code in the environment was deployed from, and provide controls that prevent deployment from untrusted sources or registries.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36064r601754_chk'
  tag severity: 'medium'
  tag gid: 'V-233128'
  tag rid: 'SV-233128r601755_rule'
  tag stig_id: 'SRG-APP-000243-CTR-000600'
  tag gtitle: 'SRG-APP-000243'
  tag fix_id: 'F-36032r601862_fix'
  tag 'documentable'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
