control 'SV-207614' do
  title 'The ESXi host SSH daemon must not allow host-based authentication.'
  desc %q(SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts. SSH's cryptographic host-based authentication is more secure than ".rhosts" authentication, since hosts are cryptographically authenticated. However, it is not recommended that hosts unilaterally trust one another, even within an organization.)
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^HostbasedAuthentication" /etc/ssh/sshd_config

If there is no output or the output is not exactly "HostbasedAuthentication no", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

Add or correct the following line in "/etc/ssh/sshd_config": 

HostbasedAuthentication no'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7869r364241_chk'
  tag severity: 'medium'
  tag gid: 'V-207614'
  tag rid: 'SV-207614r388482_rule'
  tag stig_id: 'ESXI-65-000013'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7869r364242_fix'
  tag 'documentable'
  tag legacy: ['SV-104059', 'V-93973']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
