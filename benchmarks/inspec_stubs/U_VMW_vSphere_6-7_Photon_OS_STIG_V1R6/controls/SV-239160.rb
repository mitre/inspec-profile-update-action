control 'SV-239160' do
  title 'The Photon operating system must configure sshd to disallow authentication with an empty password.'
  desc 'Blank passwords are one of the first things an attacker checks for when probing a system. Even is the user somehow has a blank password on the OS, sshd must not allow that user to log in.'
  desc 'check', 'At the command line, execute the following command:

# sshd -T|&grep -i PermitEmptyPasswords

Expected result:

PermitEmptyPasswords no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/ssh/sshd_config with a text editor.

Ensure that the "PermitEmptyPasswords" line is uncommented and set to the following:

PermitEmptyPasswords no

At the command line, execute the following command:

# service sshd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42371r675286_chk'
  tag severity: 'medium'
  tag gid: 'V-239160'
  tag rid: 'SV-239160r675288_rule'
  tag stig_id: 'PHTN-67-000089'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42330r675287_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
