control 'SV-248613' do
  title 'OL 8 must not permit direct logons to the root account using remote access via SSH.'
  desc 'Although the communications channel may be encrypted, an additional layer of security is gained by extending the policy of not logging on directly as root. In addition, logging on with a user-specific account provides individual accountability of actions performed on the system.'
  desc 'check', 'Verify remote access using SSH prevents users from logging on directly as "root" with the following command: 
 
$ sudo grep -i PermitRootLogin /etc/ssh/sshd_config 
 
PermitRootLogin no 
 
If the "PermitRootLogin" keyword is set to "yes", is missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to stop users from logging on remotely as the "root" user via SSH. 
 
Edit the appropriate "/etc/ssh/sshd_config" file to uncomment or add the line for the "PermitRootLogin" keyword and set its value to "no": 
 
PermitRootLogin no 
 
The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command: 
 
$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52047r779403_chk'
  tag severity: 'medium'
  tag gid: 'V-248613'
  tag rid: 'SV-248613r779405_rule'
  tag stig_id: 'OL08-00-010550'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-52001r779404_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
