control 'SV-218612' do
  title 'The SSH daemon must not allow host-based authentication.'
  desc 'SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.'
  desc 'check', %q(To determine how the SSH daemon's "HostbasedAuthentication" option is set, run the following command:

# grep -i HostbasedAuthentication /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value "no" is returned, then the required value is set.

If the required value is not set, this is a finding.)
  desc 'fix', %q(SSH's cryptographic host-based authentication is more secure than ".rhosts" authentication since hosts are cryptographically authenticated. However, it is not recommended that hosts unilaterally trust one another, even within an organization.

To disable host-based authentication, add or correct the following line in "/etc/ssh/sshd_config":

HostbasedAuthentication no)
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20087r556034_chk'
  tag severity: 'medium'
  tag gid: 'V-218612'
  tag rid: 'SV-218612r603259_rule'
  tag stig_id: 'GEN005527'
  tag gtitle: 'SRG-OS-000106-GPOS-00053'
  tag fix_id: 'F-20085r556035_fix'
  tag 'documentable'
  tag legacy: ['V-58537', 'SV-75259']
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
