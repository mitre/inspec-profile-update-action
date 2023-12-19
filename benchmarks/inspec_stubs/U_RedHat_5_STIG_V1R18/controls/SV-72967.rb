control 'SV-72967' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-59409r2_chk'
  tag severity: 'medium'
  tag gid: 'V-58537'
  tag rid: 'SV-72967r1_rule'
  tag stig_id: 'GEN005527'
  tag gtitle: 'GEN005527'
  tag fix_id: 'F-63919r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
