control 'SV-4249' do
  title 'The system boot loader must require authentication.'
  desc "If the system's boot loader does not require authentication, users with console access to the system may be able to alter the system boot configuration or boot the system into single user or maintenance mode, which could result in Denial-of-Service or unauthorized privileged access to the system."
  desc 'check', 'This check applies to the global zone only. Determine the type of zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

On systems that have a ZFS root, the active menu.lst file is typically located at /pool-name/boot/grub/menu.lst where "pool-name" is the mount point for the top-level dataset.

On systems that have a UFS root, the active menu.lst file is typically located at /boot/grub/menu.lst.  To locate the active GRUB menu, use the bootadm command with the list-menu option:

# bootadm list-menu

Check the menu.lst file for the use of passwords.

Procedure:
# more /pool-name/boot/grub/menu.lst
or
# more /boot/grub/menu.lst

Check for a password configuration line, such as the one below.
password --md5 <password-hash>

This line should be just below the line beginning with "timeout". Please note <password-hash> will be replaced by the actual MD5 encrypted password. If the password line is not in either of the files, this is a finding.'
  desc 'fix', 'The GRUB console boot loader can be configured to use an MD5 encrypted password by adding password --md5 password-hash to the /pool-name/boot/grub/menu.lst or /boot/grub/menu.lst file. Use grub-md5-crypt to generate MD5 passwords from the command line.'
  impact 0.7
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2059r3_chk'
  tag severity: 'high'
  tag gid: 'V-4249'
  tag rid: 'SV-4249r3_rule'
  tag stig_id: 'GEN008700'
  tag gtitle: 'GEN008700'
  tag fix_id: 'F-4160r3_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
