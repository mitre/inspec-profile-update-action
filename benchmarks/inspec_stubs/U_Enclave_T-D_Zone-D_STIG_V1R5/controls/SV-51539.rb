control 'SV-51539' do
  title 'Virtual machines used for application development and testing must not share the same physical host with DoD operational virtual machines.'
  desc 'Attacks on virtual machines from other VMs through denial of service and other attacks potentially stealing sensitive data such as source code used in application development.  It is imperative to keep DoD operational virtual machines on physically separate platforms from test and development virtual machines.'
  desc 'check', 'Review the system plan to determine whether physical hosts are sharing DoD operational and test and development virtual machines.'
  desc 'fix', 'Engineer a solution to use separate physical hosts for DoD operational and T&D virtual machines.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone D'
  tag check_id: 'C-46827r1_chk'
  tag severity: 'medium'
  tag gid: 'V-39672'
  tag rid: 'SV-51539r1_rule'
  tag stig_id: 'ENTD0330'
  tag gtitle: 'ENTD0330 - Operational along with test and developments VMs share same host.'
  tag fix_id: 'F-44680r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
