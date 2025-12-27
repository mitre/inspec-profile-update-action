control 'SV-208823' do
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

for i in /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64
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
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9076r357449_chk'
  tag severity: 'medium'
  tag gid: 'V-208823'
  tag rid: 'SV-208823r603263_rule'
  tag stig_id: 'OL6-00-000046'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-9076r357450_fix'
  tag 'documentable'
  tag legacy: ['SV-64991', 'V-50785']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
