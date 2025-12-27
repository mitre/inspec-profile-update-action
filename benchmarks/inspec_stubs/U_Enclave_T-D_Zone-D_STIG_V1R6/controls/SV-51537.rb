control 'SV-51537' do
  title 'Remote access into the test and development environment must originate from a non-DoD operational network segment.'
  desc 'If remote access is needed to access the test and development environment, it must be originated from a non-DoD operational network segment.  Examples of this are a virtual machine located on government-furnished equipment used for operational tasks, or a separate physical machine sitting in a separate network segment or VLAN.  Keeping direct access off the DoD operational network will reduce the risk of test and development data being leaked, potentially damaging or compromising live data.'
  desc 'check', 'Determine whether remote access to the test and development environment from any DoD operational network segment has been prohibited.  If no procedures exist to prohibit remote access to the test and development environment from any DoD operational network, this is a finding.'
  desc 'fix', 'Prohibit remote access from DoD operational networks.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone D'
  tag check_id: 'C-46825r1_chk'
  tag severity: 'medium'
  tag gid: 'V-39670'
  tag rid: 'SV-51537r1_rule'
  tag stig_id: 'ENTD0310'
  tag gtitle: 'ENTD0310 - Remote access originates from DoD operational networks.'
  tag fix_id: 'F-44678r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
