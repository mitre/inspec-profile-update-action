control 'SV-51485' do
  title 'The test and development infrastructure must use a gateway to separate access to DoD operational networks.'
  desc 'Acting as the first hop into a test and development environment, the gateway can implement proper routing and provide a first layer of defense against attacks and other unintentional compromise or spillage of sensitive information into the operational network.'
  desc 'check', 'Review the network diagrams and physically check to see whether the organization has a gateway implemented for the test and development environment.  If the organization has not documented or implemented a gateway for the test and development environment, this is a finding.'
  desc 'fix', 'Install a gateway to separate the test and development environment from the DoD operational network.  Document it in the test and development network diagrams.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone B'
  tag check_id: 'C-46800r2_chk'
  tag severity: 'medium'
  tag gid: 'V-39627'
  tag rid: 'SV-51485r1_rule'
  tag stig_id: 'ENTD0160'
  tag gtitle: 'ENTD0160 - The test and development environment does have a gateway.'
  tag fix_id: 'F-44639r2_fix'
  tag 'documentable'
  tag ia_controls: 'DCSP-1, ECSC-1'
end
