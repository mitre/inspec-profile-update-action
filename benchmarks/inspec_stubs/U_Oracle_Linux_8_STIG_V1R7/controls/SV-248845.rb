control 'SV-248845' do
  title 'OL 8 must mount "/dev/shm" with the "nosuid" option.'
  desc 'The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting. 
 
The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access. 
 
The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access. 
 
The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/dev/shm" is mounted with the "nosuid" option: 
 
$ sudo mount | grep /dev/shm 
 
tmpfs on /dev/shm type tmpfs (rw,nodev,nosuid,noexec,seclabel) 
 
Verify that the "nosuid" option is configured for "/dev/shm": 
 
$ sudo cat /etc/fstab | grep /dev/shm 
 
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0 
 
If results are returned and the "nosuid" option is missing, or if "/dev/shm" is mounted without the "nosuid" option, this is a finding.'
  desc 'fix', 'Configure OL 8 so that "/dev/shm" is mounted with the "nosuid" option by adding/modifying "/etc/fstab" with the following line: 
 
tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52279r780099_chk'
  tag severity: 'medium'
  tag gid: 'V-248845'
  tag rid: 'SV-248845r853854_rule'
  tag stig_id: 'OL08-00-040121'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-52233r780100_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
