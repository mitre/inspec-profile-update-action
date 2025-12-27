control 'SV-208924' do
  title 'The SSH daemon must not allow host-based authentication.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.'
  desc 'check', %q(To determine how the SSH daemon's "HostbasedAuthentication" option is set, run the following command: 

# grep -i HostbasedAuthentication /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value "no" is returned, then the required value is set. 
If the required value is not set, this is a finding.)
  desc 'fix', %q(SSH's cryptographic host-based authentication is more secure than ".rhosts" authentication, since hosts are cryptographically authenticated. However, it is not recommended that hosts unilaterally trust one another, even within an organization. 

To disable host-based authentication, add or correct the following line in "/etc/ssh/sshd_config": 

HostbasedAuthentication no)
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9177r357752_chk'
  tag severity: 'medium'
  tag gid: 'V-208924'
  tag rid: 'SV-208924r793710_rule'
  tag stig_id: 'OL6-00-000236'
  tag gtitle: 'SRG-OS-000106'
  tag fix_id: 'F-9177r357753_fix'
  tag 'documentable'
  tag legacy: ['V-50581', 'SV-64787']
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
