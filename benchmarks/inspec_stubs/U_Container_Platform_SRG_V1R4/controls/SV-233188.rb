control 'SV-233188' do
  title 'The container platform must enforce access restrictions for container platform configuration changes.'
  desc 'Configuration changes cause the container platform to change the way it operates. These changes can be used to improve the system with added features or performance, but these configuration changes can also be used to introduce malicious features and degrade performance. To control the configuration changes made to the container platform, it is important that only authorized users are allowed, through container platform enforcement, to make configuration changes.'
  desc 'check', 'Review documentation and configuration settings to determine if the container platform enforces access restrictions associated with changes to container platform components configuration. 

If the container platform does not enforce such access restrictions, this is a finding.'
  desc 'fix', 'Configure the container platform to enforce access restrictions associated with changes to the container platform components configuration.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36124r601793_chk'
  tag severity: 'medium'
  tag gid: 'V-233188'
  tag rid: 'SV-233188r879753_rule'
  tag stig_id: 'SRG-APP-000380-CTR-000900'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-36092r601880_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
