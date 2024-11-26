control 'SV-239164' do
  title 'The Photon operating system must configure sshd to ignore user-specific known_host files.'
  desc 'SSH trust relationships enable trivial lateral spread after a host compromise and therefore must be explicitly disabled. Individual users can have a local list of trusted remote machines which must also be ignored while disabling host-based authentication generally.'
  desc 'check', 'At the command line, execute the following command:

# sshd -T|&grep -i IgnoreUserKnownHosts

Expected result:

IgnoreUserKnownHosts yes

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/ssh/sshd_config with a text editor.

Ensure that the "IgnoreUserKnownHosts" line is uncommented and set to the following:

IgnoreUserKnownHosts yes

At the command line, execute the following command:

# service sshd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42375r675298_chk'
  tag severity: 'medium'
  tag gid: 'V-239164'
  tag rid: 'SV-239164r675300_rule'
  tag stig_id: 'PHTN-67-000093'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42334r675299_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
