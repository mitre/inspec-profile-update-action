control 'SV-217885' do
  title 'All system command files must have mode 755 or less permissive.'
  desc 'System binaries are executed by privileged users, as well as system services, and restrictive permissions are necessary to ensure execution of these programs cannot be co-opted.'
  desc 'check', 'System executables are stored in the following directories by default: 

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

All files in these directories should not be group-writable or world-writable. To find system executables that are group-writable or world-writable, run the following command for each directory [DIR] which contains system executables: 

$ find -L [DIR] -perm /022 -type f

If any system executables are found to be group-writable or world-writable, this is a finding.'
  desc 'fix', 'System executables are stored in the following directories by default: 

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

If any file in these directories is found to be group-writable or world-writable, correct its permission with the following command: 

# chmod go-w [FILE]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19366r376670_chk'
  tag severity: 'medium'
  tag gid: 'V-217885'
  tag rid: 'SV-217885r603264_rule'
  tag stig_id: 'RHEL-06-000047'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-19364r376671_fix'
  tag 'documentable'
  tag legacy: ['V-38469', 'SV-50269']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
