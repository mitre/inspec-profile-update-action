control 'SV-217884' do
  title 'Library files must be owned by a system account.'
  desc 'Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Proper ownership is necessary to protect the integrity of the system.'
  desc 'check', %q(System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default: 

/lib
/lib64
/usr/lib
/usr/lib64
/usr/local/lib
/usr/local/lib64

Kernel modules, which can be added to the kernel during runtime, are stored in "/lib/modules". All files in these directories should not be group-writable or world-writable.  To find shared libraries that are not owned by "root" and do not match what is expected by the RPM, run the following command:

for i in /lib /lib64 /usr/lib /usr/lib64
do
  for j in `find -L $i \! -user root`
  do
    rpm -V -f $j | grep '^.....U'
  done
done


If the command returns any results, this is a finding.)
  desc 'fix', 'System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default: 

/lib
/lib64
/usr/lib
/usr/lib64
/usr/local/lib 
/usr/local/lib64

If any file in these directories is found to be owned by a user other than “root” and does not match what is expected by the RPM, correct its ownership by running one of the following commands: 


# rpm --setugids [PACKAGE_NAME]

Or

# chown root [FILE]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19365r462367_chk'
  tag severity: 'medium'
  tag gid: 'V-217884'
  tag rid: 'SV-217884r603264_rule'
  tag stig_id: 'RHEL-06-000046'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-19363r462368_fix'
  tag 'documentable'
  tag legacy: ['V-38466', 'SV-50266']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
