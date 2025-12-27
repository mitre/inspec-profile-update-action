control 'SV-215420' do
  title 'All AIX files and directories must have a valid group owner.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Determine if any file on the system does not have a valid group owner using command:
# find / -nogroup -print 

If any such files are found, this is a finding.'
  desc 'fix', 'Change the group owner for each file without a valid group owner using command:
# chgrp <a-valid-group> /tmp/a-file-without-a-valid-group-owner'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16618r294711_chk'
  tag severity: 'medium'
  tag gid: 'V-215420'
  tag rid: 'SV-215420r508663_rule'
  tag stig_id: 'AIX7-00-003125'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16616r294712_fix'
  tag 'documentable'
  tag legacy: ['V-91689', 'SV-101787']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
