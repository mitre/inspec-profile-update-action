control 'SV-214904' do
  title 'The macOS system must be configured with the sticky bit set on all public directories.'
  desc 'The sticky bit must be set on all public directories, as it prevents users with write access to the directory from deleting or renaming files that belong to other users inside it.'
  desc 'check', 'Run the following command to view all world-writable directories that do not have the "sticky bit" set:

/usr/bin/sudo /usr/bin/find / -type d \\( -perm -0002 -a ! -perm -1000 \\)

If anything is returned, this is a finding.'
  desc 'fix', 'Run the following command to set the "sticky bit" on all world-writable directories:

/usr/bin/sudo /usr/bin/find / -type d \\( -perm -0002 -a ! -perm -1000 \\) -exec chmod +t {} \\;'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16104r397284_chk'
  tag severity: 'medium'
  tag gid: 'V-214904'
  tag rid: 'SV-214904r609363_rule'
  tag stig_id: 'AOSX-13-001120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16102r397285_fix'
  tag 'documentable'
  tag legacy: ['SV-96401', 'V-81687']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
