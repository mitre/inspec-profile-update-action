control 'SV-220125' do
  title 'The system boot loader must protect passwords using an MD5 or stronger cryptographic hash.'
  desc 'If system boot loader passwords are compromised, users with console access to the system may be able to alter the system boot configuration or boot the system into single user or maintenance mode, which could result in Denial-of-Service or unauthorized privileged access to the system.'
  desc 'check', 'This check applies to the global zone only. Determine the type of zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

On systems that have a ZFS root, the active menu.lst file is typically located at /pool-name/boot/grub/menu.lst where "pool-name" is the mount point for the top-level dataset.

On systems that have a UFS root, the active menu.lst file is typically located at /boot/grub/menu.lst.  To locate the active GRUB menu, use the bootadm command with the list-menu option:

# bootadm list-menu

Check the boot configuration for password settings.

List any password configuration from the active menu file (substitute the file determined above in place of the example file provided below, if necessary).
# grep password /pool-name/boot/grub/menu.lst
or
# grep password /boot/grub/menu.lst

Check for a password configuration line, such as:
password --md5 <password-hash>

If the boot loader passwords are not protected using an MD5 hash or stronger, this is a finding.'
  desc 'fix', 'Configure the GRUB bootloader to require a password.

Procedure:

Obtain the location of the active GRUB menu file.
# bootadm list-menu

Create a password hash using GRUB. The location of the GRUB binary may be different based on the specific system.
# /boot/grub/bin/grub
grub> md5crypt
Password: <password>
Encrypted: <password hash>
grub> quit

The encrypted password hash will be returned.

Edit the GRUB menu configuration file, and add a line such as the following, substituting the password hash obtained above:

password --md5 <password hash>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36433r602902_chk'
  tag severity: 'medium'
  tag gid: 'V-220125'
  tag rid: 'SV-220125r603266_rule'
  tag stig_id: 'GEN008710'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-36397r602903_fix'
  tag 'documentable'
  tag legacy: ['V-24624', 'SV-42317']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
