control 'SV-239161' do
  title 'The Photon operating system must configure sshd to disallow compression of the encrypted session stream.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection.'
  desc 'check', 'At the command line, execute the following command:

# sshd -T|&grep -i Compression

Expected result:

Compression no

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/ssh/sshd_config with a text editor.

Ensure that the "Compression" line is uncommented and set to the following:

Compression no

At the command line, execute the following command:

# service sshd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42372r675289_chk'
  tag severity: 'medium'
  tag gid: 'V-239161'
  tag rid: 'SV-239161r675291_rule'
  tag stig_id: 'PHTN-67-000090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42331r675290_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
