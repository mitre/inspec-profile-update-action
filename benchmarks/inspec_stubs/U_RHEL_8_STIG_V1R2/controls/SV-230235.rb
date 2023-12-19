control 'SV-230235' do
  title 'RHEL 8 operating systems booted with a BIOS must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 8 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.'
  desc 'check', 'For systems that use UEFI, this is Not Applicable.

Check to see if an encrypted root password is set. On systems that use a BIOS, use the following command:

$ sudo grep -iw grub2_password /boot/grub2/user.cfg

GRUB2_PASSWORD=grub.pbkdf2.sha512.[password_hash]

If the root password does not begin with "grub.pbkdf2.sha512", this is a finding.

Verify that a unique name is set as the "superusers":

$ sudo grep -iw "superusers" /boot/grub2/grub.cfg
set superusers="[someuniquestringhere]"
export superusers

If "superusers" is not set to a unique name or is missing a name, this is a finding.'
  desc 'fix', 'Configure the system to require a grub bootloader password for the grub superuser account.

Generate an encrypted grub2 password for the grub superuser account with the following command:

$ sudo grub2-setpassword
Enter password:
Confirm password:

Edit the /boot/grub2/grub.cfg file and add or modify the following lines in the "### BEGIN /etc/grub.d/01_users ###" section:

set superusers="[someuniquestringhere]"
export superusers'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32904r567451_chk'
  tag severity: 'high'
  tag gid: 'V-230235'
  tag rid: 'SV-230235r627750_rule'
  tag stig_id: 'RHEL-08-010150'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-32879r567452_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
