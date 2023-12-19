control 'SV-239163' do
  title 'The Photon operating system must configure sshd to ignore user-specific trusted hosts lists.'
  desc 'SSH trust relationships enable trivial lateral spread after a host compromise and therefore must be explicitly disabled. Individual users can have a local list of trusted remote machines, which must also be ignored while disabling host-based authentication generally.'
  desc 'check', 'At the command line, execute the following command:

# sshd -T|&grep -i IgnoreRhosts

Expected result:

IgnoreRhosts yes

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/ssh/sshd_config with a text editor.

Ensure that the "IgnoreRhosts" line is uncommented and set to the following:

IgnoreRhosts yes

At the command line, execute the following command:

# service sshd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42374r675295_chk'
  tag severity: 'medium'
  tag gid: 'V-239163'
  tag rid: 'SV-239163r675297_rule'
  tag stig_id: 'PHTN-67-000092'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42333r675296_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
