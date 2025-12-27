control 'SV-217998' do
  title 'The SSH daemon must ignore .rhosts files.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.'
  desc 'check', %q(To determine how the SSH daemon's "IgnoreRhosts" option is set, run the following command: 

# grep -i IgnoreRhosts /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value "yes" is returned, then the required value is set. 
If the required value is not set, this is a finding.)
  desc 'fix', 'SSH can emulate the behavior of the obsolete rsh command in allowing users to enable insecure access to their accounts via ".rhosts" files. 

To ensure this behavior is disabled, add or correct the following line in "/etc/ssh/sshd_config": 

IgnoreRhosts yes'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19479r377009_chk'
  tag severity: 'medium'
  tag gid: 'V-217998'
  tag rid: 'SV-217998r603264_rule'
  tag stig_id: 'RHEL-06-000234'
  tag gtitle: 'SRG-OS-000106'
  tag fix_id: 'F-19477r377010_fix'
  tag 'documentable'
  tag legacy: ['V-38611', 'SV-50412']
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
