control 'SV-248697' do
  title 'OL 8 user account passwords must be configured so that existing passwords are restricted to a 60-day maximum lifetime.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If OL 8 does not limit the lifetime of passwords and force users to change their passwords, there is the risk that OL 8 passwords could be compromised.'
  desc 'check', %q(Verify the maximum time period for existing passwords is restricted to 60 days with the following commands: 
 
$ sudo awk -F: '$5 > 60 {print $1 " " $5}' /etc/shadow 
 
$ sudo awk -F: '$5 <= 0 {print $1 " " $5}' /etc/shadow 
 
If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure non-compliant accounts to enforce a 60-day maximum password lifetime restriction. 
 
$ sudo chage -M 60 [user]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52131r779655_chk'
  tag severity: 'medium'
  tag gid: 'V-248697'
  tag rid: 'SV-248697r779657_rule'
  tag stig_id: 'OL08-00-020210'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag fix_id: 'F-52085r779656_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
