control 'SV-239155' do
  title 'The Photon operating system must configure sshd to disable environment processing.'
  desc 'Enabling environment processing may enable users to bypass access restrictions in some configurations and must therefore be disabled.'
  desc 'check', 'At the command line, execute the following command:

sshd -T|&grep -i PermitUserEnvironment

Expected result:

PermitUserEnvironment no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/ssh/sshd_config with a text editor.

Ensure that the "PermitUserEnvironment" line is uncommented and set to the following:

PermitUserEnvironment no

At the command line, execute the following command:

# service sshd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42366r675271_chk'
  tag severity: 'medium'
  tag gid: 'V-239155'
  tag rid: 'SV-239155r675273_rule'
  tag stig_id: 'PHTN-67-000084'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42325r675272_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
