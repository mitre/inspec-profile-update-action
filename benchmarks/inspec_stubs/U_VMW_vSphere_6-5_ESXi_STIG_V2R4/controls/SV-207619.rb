control 'SV-207619' do
  title 'The ESXi host SSH daemon must not permit GSSAPI authentication.'
  desc 'GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system’s GSSAPI to remote hosts, increasing the attack surface of the system.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^GSSAPIAuthentication" /etc/ssh/sshd_config

If there is no output or the output is not exactly "GSSAPIAuthentication no", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

GSSAPIAuthentication no'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7874r364256_chk'
  tag severity: 'low'
  tag gid: 'V-207619'
  tag rid: 'SV-207619r388482_rule'
  tag stig_id: 'ESXI-65-000018'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7874r364257_fix'
  tag 'documentable'
  tag legacy: ['V-93983', 'SV-104069']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
