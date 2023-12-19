control 'SV-51526' do
  title 'The Zone D test and development environment must be physically separate and isolated from any DoD operational network.'
  desc 'Systems found in the Zone D test and development environment are typically non-IA-compliant test systems that include hardware, software, or development systems.  These systems typically do not follow the appropriate best security practices.  Therefore, if they are connected to any operational network, it is possible to infect live data or degrade infrastructure in an operational network.'
  desc 'check', "Review the organization's network diagrams for the Zone D test and development environment and work with the network reviewer to determine whether the environment is physically separate and isolated from any DoD operational network.  If physical separation or isolation is not shown for the Zone D test and development environment on the network diagrams, this is a finding."
  desc 'fix', 'Physically separate and isolate the Zone D test and development environment from any DoD operational network.'
  impact 0.7
  ref 'DPMS Target Test Enclave - Zone D'
  tag check_id: 'C-46814r3_chk'
  tag severity: 'high'
  tag gid: 'V-39659'
  tag rid: 'SV-51526r2_rule'
  tag stig_id: 'ENTD0200'
  tag gtitle: 'ENTD0200 - Zone D test and development environment not physically separate.'
  tag fix_id: 'F-44667r3_fix'
  tag 'documentable'
end
