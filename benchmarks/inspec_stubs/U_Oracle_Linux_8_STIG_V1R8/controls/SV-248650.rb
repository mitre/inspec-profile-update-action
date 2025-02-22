control 'SV-248650' do
  title 'OL 8 must not allow users to override SSH environment variables.'
  desc 'SSH environment options potentially allow users to bypass access restriction in some configurations.'
  desc 'check', 'Verify that unattended or automatic login via SSH is disabled with the following command:

$ sudo grep -ir PermitUserEnvironment /etc/ssh/sshd_config*

PermitUserEnvironment no

If "PermitUserEnvironment" is set to "yes", is missing completely, or is commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure OL 8 to allow the SSH daemon to not allow unattended or automatic login to the system. 
 
Add or edit the following line in the "/etc/ssh/sshd_config" file: 
 
PermitUserEnvironment no 
 
The SSH daemon must be restarted for the changes to take effect. To restart the SSH daemon, run the following command: 
 
$ sudo systemctl restart sshd.service'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52084r858579_chk'
  tag severity: 'high'
  tag gid: 'V-248650'
  tag rid: 'SV-248650r877377_rule'
  tag stig_id: 'OL08-00-010830'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-52038r779515_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
