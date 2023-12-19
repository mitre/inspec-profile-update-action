control 'SV-221701' do
  title 'Oracle Linux operating systems prior to version 7.2 using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for Oracle Linux 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.'
  desc 'check', 'For systems that use BIOS, this is Not Applicable.
For systems that are running Oracle Linux 7.2 or newer, this is Not Applicable.

Check to see if an encrypted root password is set. On systems that use UEFI, use the following command:

# grep -i password /boot/efi/EFI/redhat/grub.cfg

password_pbkdf2 [superusers-account] [password-hash]

If the root password entry does not begin with "password_pbkdf2", this is a finding.

If the "superusers-account" is not set to "root", this is a finding.'
  desc 'fix', 'Configure the system to encrypt the boot password for root.

Generate an encrypted grub2 password for root with the following command:

Note: The hash generated is an example.

# grub2-mkpasswd-pbkdf2

Enter Password:
Reenter Password:
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.F3A7CFAA5A51EED123BE8238C23B25B2A6909AFC9812F0D45

Edit "/etc/grub.d/40_custom" and add the following lines below the comments:

# vi /etc/grub.d/40_custom

set superusers="root"

password_pbkdf2 root {hash from grub2-mkpasswd-pbkdf2 command}

Generate a new "grub.conf" file with the new password with the following commands:

# grub2-mkconfig --output=/tmp/grub2.cfg
# mv /tmp/grub2.cfg /boot/efi/EFI/redhat/grub.cfg'
  impact 0.7
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23416r419175_chk'
  tag severity: 'high'
  tag gid: 'V-221701'
  tag rid: 'SV-221701r603260_rule'
  tag stig_id: 'OL07-00-010490'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-23405r419176_fix'
  tag 'documentable'
  tag legacy: ['V-99141', 'SV-108245']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
