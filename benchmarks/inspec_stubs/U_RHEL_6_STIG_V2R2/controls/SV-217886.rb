control 'SV-217886' do
  title 'All system command files must be owned by root.'
  desc 'System binaries are executed by privileged users as well as system services, and restrictive permissions are necessary to ensure that their execution of these programs cannot be co-opted.'
  desc 'check', 'System executables are stored in the following directories by default: 

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

All files in these directories should not be group-writable or world-writable. To find system executables that are not owned by "root", run the following command for each directory [DIR] which contains system executables: 

$ find -L [DIR] \\! -user root


If any system executables are found to not be owned by root, this is a finding.'
  desc 'fix', 'System executables are stored in the following directories by default: 

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

If any file [FILE] in these directories is found to be owned by a user other than root, correct its ownership with the following command: 

# chown root [FILE]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19367r376673_chk'
  tag severity: 'medium'
  tag gid: 'V-217886'
  tag rid: 'SV-217886r603264_rule'
  tag stig_id: 'RHEL-06-000048'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-19365r376674_fix'
  tag 'documentable'
  tag legacy: ['V-38472', 'SV-50272']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
