control 'SV-244530' do
  title 'RHEL 8 must prevent files with the setuid and setgid bit set from being executed on the /boot/efi directory.'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(For systems that use BIOS, this is Not Applicable.

Verify the /boot/efi directory is mounted with the "nosuid" option with the following command:

$ sudo mount | grep '\s/boot/efi\s'

/dev/sda1 on /boot/efi type xfs (rw,nosuid,relatime,seclabe,attr2,inode64,noquota)

If the /boot/efi file system does not have the "nosuid" option set, this is a finding.)
  desc 'fix', 'Configure the "/etc/fstab" to use the "nosuid" option on the /boot/efi directory.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-47805r743837_chk'
  tag severity: 'medium'
  tag gid: 'V-244530'
  tag rid: 'SV-244530r743839_rule'
  tag stig_id: 'RHEL-08-010572'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-47762r743838_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
