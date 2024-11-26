control 'SV-239162' do
  title 'The Photon operating system must configure sshd to display the last login immediately after authentication.'
  desc 'Providing users with feedback on the last time they logged on via SSH facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', 'At the command line, execute the following command:

# sshd -T|&grep -i PrintLastLog

Expected result:

PrintLastLog yes

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/ssh/sshd_config with a text editor.

Ensure that the "PrintLastLog" line is uncommented and set to the following:

PrintLastLog yes

At the command line, execute the following command:

# service sshd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42373r675292_chk'
  tag severity: 'medium'
  tag gid: 'V-239162'
  tag rid: 'SV-239162r675294_rule'
  tag stig_id: 'PHTN-67-000091'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42332r675293_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
