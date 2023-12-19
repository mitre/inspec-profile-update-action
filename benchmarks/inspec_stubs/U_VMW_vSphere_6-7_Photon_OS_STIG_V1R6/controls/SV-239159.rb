control 'SV-239159' do
  title 'The Photon operating system must configure sshd to use privilege separation.'
  desc 'Privilege separation in sshd causes the process to drop root privileges when not needed, which would decrease the impact of software vulnerabilities in the unprivileged section.'
  desc 'check', 'At the command line, execute the following command:

# sshd -T|&grep -i UsePrivilegeSeparation

Expected result:

UsePrivilegeSeparation yes

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/ssh/sshd_config with a text editor.

Ensure that the "UsePrivilegeSeparation" line is uncommented and set to the following:

UsePrivilegeSeparation yes

At the command line, execute the following command:

# service sshd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42370r675283_chk'
  tag severity: 'medium'
  tag gid: 'V-239159'
  tag rid: 'SV-239159r675285_rule'
  tag stig_id: 'PHTN-67-000088'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42329r675284_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
