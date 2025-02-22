control 'SV-202048' do
  title 'The network device must limit privileges to change the software resident within software libraries.'
  desc 'Changes to any software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. If the network device were to enable non-authorized users to make changes to software libraries, those changes could be implemented without undergoing testing, validation, and approval.'
  desc 'check', 'Determine if the network device limits privileges to change the software resident within software libraries.

If it does not limit privileges to change the software resident within software libraries, this is a finding.'
  desc 'fix', 'Configure the network device to limit privileges to change the software resident within software libraries.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2174r381749_chk'
  tag severity: 'medium'
  tag gid: 'V-202048'
  tag rid: 'SV-202048r879586_rule'
  tag stig_id: 'SRG-APP-000133-NDM-000244'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-2175r381750_fix'
  tag 'documentable'
  tag legacy: ['SV-69561', 'V-55315']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
