control 'SV-90813' do
  title 'The OS X system must be configured with the sticky bit set on all public directories.'
  desc 'The sticky bit must be set on all public directories, as it prevents users with write access to the directory from deleting or renaming files that belong to other users inside it.'
  desc 'check', 'Run the following command to view all world-writable directories that do not have the "sticky bit" set:

/usr/bin/sudo /usr/bin/find / -type d \\( -perm -0002 -a ! -perm -1000 \\)

If anything is returned, this is a finding.'
  desc 'fix', 'Run the following command to set the "sticky bit" on all world-writable directories:

/usr/bin/sudo /usr/bin/find / -type d \\( -perm -0002 -a ! -perm -1000 \\) -exec chmod +t {} \\;'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75811r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76125'
  tag rid: 'SV-90813r1_rule'
  tag stig_id: 'AOSX-12-001120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82763r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
