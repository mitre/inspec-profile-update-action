control 'SV-16833' do
  title 'VI Console is used to administer virtual machines.'
  desc 'The VI Console allows a user to connect to the console of a virtual machine, similar to seeing what a physical server monitor would show. However, the VI Console also provides power management and removable device connectivity controls, which could potentially allow a malicious user to bring down a virtual machine. In addition, it also has a performance impact on the service console, especially if many VI Console sessions are open simultaneously. To prevent performance issues and potential unauthorized users from accessing the VI Console, users should use remote management services, such as terminal services and ssh, to interact with virtual machines.'
  desc 'check', 'Ask the IAO/SA what tools are used to administer virtual machines remotely.  If the response includes the VI console, this is a finding.'
  desc 'fix', 'Use third party tools to administer virtual machines.'
  impact 0.3
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16251r1_chk'
  tag severity: 'low'
  tag gid: 'V-15892'
  tag rid: 'SV-16833r1_rule'
  tag stig_id: 'ESX0960'
  tag gtitle: 'VI Console is used to administer virtual machines'
  tag fix_id: 'F-15852r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECSC-1'
end
