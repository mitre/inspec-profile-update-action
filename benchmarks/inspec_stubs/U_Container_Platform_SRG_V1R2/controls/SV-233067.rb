control 'SV-233067' do
  title 'The container platform must limit privileges to the container platform runtime.'
  desc 'To control what is instantiated within the container platform, it is important to control access to the runtime. Without this control, container platform specific services and customer services can be introduced without receiving approval and going through proper testing. Only those individuals and roles approved by the organization can have access to the container platform runtime.'
  desc 'check', 'Review the container platform runtime configuration to determine if the level of access to the runtime is controlled through user privileges. 

Attempt to perform runtime operations to determine if the privileges are enforced. 

If the container platform runtime is not limited through user privileges or the user privileges are not enforced, this is a finding.'
  desc 'fix', 'Configure the container platform to use and enforce user privileges when accessing the container platform runtime.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36003r601700_chk'
  tag severity: 'medium'
  tag gid: 'V-233067'
  tag rid: 'SV-233067r601701_rule'
  tag stig_id: 'SRG-APP-000133-CTR-000295'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-35971r600689_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
