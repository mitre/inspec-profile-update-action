control 'SV-244558' do
  title 'Red Hat Enterprise Linux operating systems version 7.2 or newer booted with United Extensible Firmware Interface (UEFI) must have a unique name for the grub superusers account when booting into single-user mode and maintenance.'
  desc 'If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.
The GRUB 2 superuser account is an account of last resort. Establishing a unique username for this account hardens the boot loader against brute force attacks. Due to the nature of the superuser account database being distinct from the OS account database, this allows the use of a username that is not among those within the OS account database. Examples of non-unique superusers names are root, superuser, unlock, etc.'
  desc 'check', 'For systems that use BIOS, this is Not Applicable.

For systems that are running a version of RHEL prior to 7.2, this is Not Applicable.

Verify that a unique name is set as the "superusers" account:

$ sudo grep -iw "superusers" /boot/efi/EFI/redhat/grub.cfg
    set superusers="[someuniquestringhere]"
    export superusers

If "superusers" is identical to any OS account name or is missing a name, this is a finding.'
  desc 'fix', 'Configure the system to have a unique name for the grub superusers account.

Edit the /boot/efi/EFI/redhat/grub.cfg file and add or modify the following lines in the "### BEGIN /etc/grub.d/01_users ###" section:

set superusers="[someuniquestringhere]"
export superusers
password_pbkdf2 [someuniquestringhere] ${GRUB2_PASSWORD}'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-47833r792839_chk'
  tag severity: 'medium'
  tag gid: 'V-244558'
  tag rid: 'SV-244558r792840_rule'
  tag stig_id: 'RHEL-07-010492'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-47790r744065_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
