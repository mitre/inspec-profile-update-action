control 'SV-248707' do
  title 'The OL 8 lastlog command must be group-owned by root.'
  desc 'Unauthorized disclosure of the contents of the /var/log/lastlog file can reveal system data to attackers, thus compromising its confidentiality.'
  desc 'check', 'Verify the "lastlog" command is group-owned by root with the following command: 
 
$ sudo ls -l /usr/bin/lastlog
 
-rwxr-x---. 1  root  root  21200 Nov  4   22:51  /usr/bin/lastlog
 
If the "lastlog" command is not group-owned by root, this is a finding.'
  desc 'fix', 'Configure the "lastlog" command for OL 8 to be group-owned by root with the following command:  
 
$ sudo chgrp root /usr/bin/lastlog'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52141r779685_chk'
  tag severity: 'medium'
  tag gid: 'V-248707'
  tag rid: 'SV-248707r779687_rule'
  tag stig_id: 'OL08-00-020264'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-52095r779686_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
