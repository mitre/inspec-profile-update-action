control 'SV-217883' do
  title 'Library files must have mode 0755 or less permissive.'
  desc 'Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Restrictive permissions are necessary to protect the integrity of the system.'
  desc 'check', 'System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default: 

/lib
/lib64
/usr/lib
/usr/lib64


Kernel modules, which can be added to the kernel during runtime, are stored in "/lib/modules". All files in these directories should not be group-writable or world-writable. To find shared libraries that are group-writable or world-writable, run the following command for each directory [DIR] which contains shared libraries: 

$ find -L [DIR] -perm /022 -type f


If any of these files (excluding broken symlinks) are group-writable or world-writable, this is a finding.'
  desc 'fix', 'System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default: 

/lib
/lib64
/usr/lib
/usr/lib64

If any file in these directories is found to be group-writable or world-writable, correct its permission with the following command: 

# chmod go-w [FILE]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19364r376664_chk'
  tag severity: 'medium'
  tag gid: 'V-217883'
  tag rid: 'SV-217883r603264_rule'
  tag stig_id: 'RHEL-06-000045'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-19362r376665_fix'
  tag 'documentable'
  tag legacy: ['V-38465', 'SV-50265']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
