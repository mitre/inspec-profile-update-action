control 'SV-239126' do
  title 'The Photon operating system must configure sshd with a specific ListenAddress.'
  desc 'Without specifying a ListenAddress, sshd will listen on all interfaces. In situations with multiple interfaces, this may not be intended behavior and could lead to offering remote access on an unapproved network.'
  desc 'check', 'At the command line, execute the following command:

# sshd -T|&grep -i ListenAddress

If the ListenAddress is not configured to the VCSA management IP, this is a finding.'
  desc 'fix', 'Open /etc/ssh/sshd_config with a text editor.

Ensure that the "ListenAddress" line is uncommented and set to a valid local IP:

Example:

ListenAddress 169.254.1.2

Replace "169.254.1.2" with the management address of the VCSA.

At the command line, execute the following command:

# service sshd reload'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42337r675184_chk'
  tag severity: 'medium'
  tag gid: 'V-239126'
  tag rid: 'SV-239126r856044_rule'
  tag stig_id: 'PHTN-67-000055'
  tag gtitle: 'SRG-OS-000297-GPOS-00115'
  tag fix_id: 'F-42296r675185_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
