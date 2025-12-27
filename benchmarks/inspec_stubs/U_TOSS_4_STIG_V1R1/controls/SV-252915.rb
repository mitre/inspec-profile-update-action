control 'SV-252915' do
  title 'TOSS must not permit direct logons to the root account using remote access from outside of the system via SSH.'
  desc 'Even though the communications channel may be encrypted, an additional layer of security is gained by extending the policy of not logging on directly as root. In addition, logging on with a user-specific account provides individual accountability of actions performed on the system.'
  desc 'check', 'Verify remote access from outside the system using SSH prevents users from logging on directly as "root."

Check that SSH prevents users from logging on directly as "root" with the following command:

$ sudo grep -i PermitRootLogin /etc/ssh/sshd_config

PermitRootLogin no

If the "PermitRootLogin" keyword is set to "yes", is missing, or is commented out, and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure TOSS to stop users from logging on remotely from outside of the cluster as the "root" user via SSH.

Edit the appropriate "/etc/ssh/sshd_config" file to uncomment or add the line for the "PermitRootLogin" keyword and set its value to "no":

PermitRootLogin no

The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command:

$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56368r824067_chk'
  tag severity: 'medium'
  tag gid: 'V-252915'
  tag rid: 'SV-252915r824069_rule'
  tag stig_id: 'TOSS-04-010040'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-56318r824068_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
