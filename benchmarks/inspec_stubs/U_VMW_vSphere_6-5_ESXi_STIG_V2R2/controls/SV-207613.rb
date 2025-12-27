control 'SV-207613' do
  title 'The ESXi host SSH daemon must ignore .rhosts files.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts. SSH can emulate the behavior of the obsolete rsh command in allowing users to enable insecure access to their accounts via ".rhosts" files.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^IgnoreRhosts" /etc/ssh/sshd_config

If there is no output or the output is not exactly "IgnoreRhosts yes", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

Add or correct the following line in "/etc/ssh/sshd_config": 

IgnoreRhosts yes'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7868r364238_chk'
  tag severity: 'medium'
  tag gid: 'V-207613'
  tag rid: 'SV-207613r378856_rule'
  tag stig_id: 'ESXI-65-000012'
  tag gtitle: 'SRG-OS-000107-VMM-000530'
  tag fix_id: 'F-7868r364239_fix'
  tag 'documentable'
  tag legacy: ['V-93971', 'SV-104057']
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
