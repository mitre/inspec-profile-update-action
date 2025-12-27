control 'SV-51538' do
  title 'Installation of operating systems on systems and devices in the test and development environment must be logically separated to prohibit access to any operational network.'
  desc 'Systems are most vulnerable to attack during the installation of an operating system because no security controls have been put in place to protect the system.  It is very important to block all access to a system while the operating system is being installed and configured until such time that security controls can be implemented.'
  desc 'check', 'Determine whether the organization has a connection approval policy on the installation of operating systems within the test and development environment.  The policy must include either physically disconnecting or blocking the system at the firewall in order to achieve complete isolation from any network traffic.  If no connection approval policy has been developed, this is a finding.'
  desc 'fix', 'Create a policy to ensure the test or development system is physically disconnected or blocked at the firewall from any external network during the installation of an operating system.'
  impact 0.3
  ref 'DPMS Target Test Enclave - Zone A'
  tag check_id: 'C-46826r1_chk'
  tag severity: 'low'
  tag gid: 'V-39671'
  tag rid: 'SV-51538r1_rule'
  tag stig_id: 'ENTD0320'
  tag gtitle: 'ENTD0320 - Installation of operating systems and devices not logically separated.'
  tag fix_id: 'F-44679r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
