control 'SV-51292' do
  title 'Network infrastructure and systems supporting the test and development environment must be managed from a management network.'
  desc 'It is important to restrict administrative access to the supporting network infrastructure and systems in the test and development environment, as it reduces the risk of data theft or interception from an attacker on the operational network.'
  desc 'check', 'Review the network diagrams to determine whether a management network has been established to manage the network infrastructure and systems supporting the test and development environment.  If a management network has not been established to manage the test and development environment infrastructure, this is a finding.'
  desc 'fix', 'Engineer a management network solution and document it within the test and development network diagrams.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone B'
  tag check_id: 'C-46708r2_chk'
  tag severity: 'medium'
  tag gid: 'V-39434'
  tag rid: 'SV-51292r1_rule'
  tag stig_id: 'ENTD0040'
  tag gtitle: 'ENTD0040 - The test and development infrastructure is not managed through management network.'
  tag fix_id: 'F-44447r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
