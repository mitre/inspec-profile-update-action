control 'SV-248847' do
  title 'OL 8 must mount "/tmp" with the "nodev" option.'
  desc 'The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting. 
 
The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access. 
 
The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access. 
 
The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/tmp" is mounted with the "nodev" option:

$ sudo mount | grep /tmp

/dev/mapper/ol-tmp on /tmp type xfs (rw,nodev,nosuid,noexec,seclabel)

Verify that the "nodev" option is configured for /tmp:

$ sudo cat /etc/fstab | grep /tmp

/dev/mapper/ol-tmp /tmp xfs defaults,nodev,nosuid,noexec 0 0

If results are returned and the "nodev" option is missing, or if /tmp is mounted without the "nodev" option, this is a finding.'
  desc 'fix', 'Configure the system so that /tmp is mounted with the "nodev" option by adding /modifying the /etc/fstab with the following line:

/dev/mapper/ol-tmp /tmp xfs defaults,nodev,nosuid,noexec 0 0'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52281r780105_chk'
  tag severity: 'medium'
  tag gid: 'V-248847'
  tag rid: 'SV-248847r853856_rule'
  tag stig_id: 'OL08-00-040123'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-52235r780106_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
