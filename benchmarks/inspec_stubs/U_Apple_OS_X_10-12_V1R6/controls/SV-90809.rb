control 'SV-90809' do
  title 'The OS X system must be configured with all public directories owned by root or an application account.'
  desc %q(All public directories must be owned by "root", the local admin user, or an application account. Directory owners have permission to delete any files contained in that directory, even if the files are owned by other user accounts. By setting the owner to an administrator or application account, regular users will not be permitted to delete each other's files.)
  desc 'check', 'To display all directories that are writable by all and not owned by "root", run the following command:

/usr/bin/sudo find / -type d -perm +o+w -not -uid 0

If anything is returned, and those directories are not owned by root or application account, this is a finding.'
  desc 'fix', 'To change the ownership of any finding, run the following command:

/usr/bin/sudo find / -type d -perm +o+w -not -uid 0 -exec chown root {} \\;'
  impact 0.5
  ref 'DPMS Target Mac OS 10.12 Workstation'
  tag check_id: 'C-75807r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76121'
  tag rid: 'SV-90809r1_rule'
  tag stig_id: 'AOSX-12-001110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-82759r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
