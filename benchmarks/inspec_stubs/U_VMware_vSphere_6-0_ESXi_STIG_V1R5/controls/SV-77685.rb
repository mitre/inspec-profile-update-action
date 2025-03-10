control 'SV-77685' do
  title 'The SSH daemon must not allow host-based authentication.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.'
  desc 'check', %q(To verify how the SSH daemon's "HostbasedAuthentication" option is set, run the following command: 

# grep -i "^HostbasedAuthentication" /etc/ssh/sshd_config

If there is no output or the output is not exactly "HostbasedAuthentication no", this is a finding.)
  desc 'fix', %q(SSH's cryptographic host-based authentication is more secure than ".rhosts" authentication, since hosts are cryptographically authenticated. However, it is not recommended that hosts unilaterally trust one another, even within an organization. 

Add or correct the following line in "/etc/ssh/sshd_config": 

HostbasedAuthentication no)
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63929r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63195'
  tag rid: 'SV-77685r1_rule'
  tag stig_id: 'ESXI-06-000013'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69113r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
