control 'SV-208801' do
  title 'The system must use a Linux Security Module configured to enforce limits on system services.'
  desc 'Setting the SELinux state to enforcing ensures SELinux is able to confine potentially compromised processes to the security policy, which is designed to prevent them from causing damage to the system or further elevating their privileges.'
  desc 'check', 'Check the file "/etc/selinux/config" and ensure the following line appears:

SELINUX=enforcing

If SELINUX is not set to enforcing, this is a finding.'
  desc 'fix', 'The SELinux state should be set to "enforcing" at system boot time. In the file "/etc/selinux/config", add or correct the following line to configure the system to boot into enforcing mode:

SELINUX=enforcing'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9054r357383_chk'
  tag severity: 'medium'
  tag gid: 'V-208801'
  tag rid: 'SV-208801r793586_rule'
  tag stig_id: 'OL6-00-000020'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9054r357384_fix'
  tag 'documentable'
  tag legacy: ['SV-73797', 'V-59367']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
