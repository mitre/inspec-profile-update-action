control 'SV-250591' do
  title 'The SSH daemon must be configured to not allow TCP connection forwarding.'
  desc 'SSH TCP connection forwarding provides a mechanism to establish TCP connections proxied by the SSH server. This function can provide similar convenience to a Virtual Private Network (VPN) with the similar risk of providing a path to circumvent firewalls and network ACLs.'
  desc 'check', %q(Disable lock down mode.
Enable the ESXi Shell. Check the SSH daemon configuration for the TCP connection forwarding setting. # grep -i AllowTCPForwarding /etc/ssh/sshd_config | grep -v '^#'

If "AllowTCPForwarding" is set  to "yes", this is a finding.

Re-enable lock down mode.)
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell.

Edit the SSH daemon configuration and add/modify the "AllowTCPForwarding" configuration setting it to "no".
# vi /etc/ssh/sshd_config

Re-enable lock down mode.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54026r798770_chk'
  tag severity: 'low'
  tag gid: 'V-250591'
  tag rid: 'SV-250591r798772_rule'
  tag stig_id: 'GEN005515-ESXI5-000100'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53980r798771_fix'
  tag 'documentable'
  tag legacy: ['V-39248', 'SV-51064']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
