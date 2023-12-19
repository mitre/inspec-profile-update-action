control 'SV-77683' do
  title 'The SSH daemon must ignore .rhosts files.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.'
  desc 'check', %q(To verify how the SSH daemon's "IgnoreRhosts" option is set, run the following command: 

# grep -i "^IgnoreRhosts" /etc/ssh/sshd_config

If there is no output or the output is not exactly "IgnoreRhosts yes", this is a finding.)
  desc 'fix', 'SSH can emulate the behavior of the obsolete rsh command in allowing users to enable insecure access to their accounts via ".rhosts" files. 

Add or correct the following line in "/etc/ssh/sshd_config": 

IgnoreRhosts yes'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63927r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63193'
  tag rid: 'SV-77683r1_rule'
  tag stig_id: 'ESXI-06-000012'
  tag gtitle: 'SRG-OS-000107-VMM-000530'
  tag fix_id: 'F-69111r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
