control 'SV-230522' do
  title 'RHEL 8 must mount /var/tmp with the noexec option.'
  desc 'The organization must identify authorized software programs and permit execution of authorized software. The process used to identify software programs that are authorized to execute on organizational information systems is commonly referred to as whitelisting.

The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.

The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify "/var/tmp" is mounted with the "noexec" option:

$ sudo mount | grep /var/tmp

/dev/mapper/rhel-var-tmp on /var/tmp type xfs (rw,nodev,nosuid,noexec,seclabel)

Verify that the "noexec" option is configured for /var/tmp:

$ sudo cat /etc/fstab | grep /var/tmp

/dev/mapper/rhel-var-tmp /var/tmp xfs defaults,nodev,nosuid,noexec 0 0

If results are returned and the "noexec" option is missing, or if /var/tmp is mounted without the "noexec" option, this is a finding.'
  desc 'fix', 'Configure the system so that /var/tmp is mounted with the "noexec" option by adding /modifying the /etc/fstab with the following line:

/dev/mapper/rhel-var-tmp /var/tmp xfs defaults,nodev,nosuid,noexec 0 0'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-33191r792931_chk'
  tag severity: 'medium'
  tag gid: 'V-230522'
  tag rid: 'SV-230522r792933_rule'
  tag stig_id: 'RHEL-08-040134'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-33166r792932_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
