control 'SV-204440' do
  title 'Red Hat Enterprise Linux operating systems version 7.2 or newer using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.'
  desc 'check', 'For systems that use BIOS, this is Not Applicable.

For systems that are running a version of RHEL prior to 7.2, this is Not Applicable.

Check to see if an encrypted grub superusers password is set. On systems that use UEFI, use the following command:

$ sudo grep -iw grub2_password /boot/efi/EFI/redhat/user.cfg
GRUB2_PASSWORD=grub.pbkdf2.sha512.[password_hash]

If the grub superusers password does not begin with "grub.pbkdf2.sha512", this is a finding.'
  desc 'fix', 'Configure the system to encrypt the boot password for the grub superusers account with the grub2-setpassword command, which creates/overwrites the /boot/efi/EFI/redhat/user.cfg file.

Generate an encrypted grub2 password for the grub superusers account with the following command:

$ sudo grub2-setpassword
Enter password:
Confirm password:'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4564r744096_chk'
  tag severity: 'high'
  tag gid: 'V-204440'
  tag rid: 'SV-204440r744098_rule'
  tag stig_id: 'RHEL-07-010491'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-4564r744097_fix'
  tag 'documentable'
  tag legacy: ['SV-95719', 'V-81007']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
