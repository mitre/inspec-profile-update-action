control 'SV-234820' do
  title 'SUSE operating systems with Unified Extensible Firmware Interface (UEFI) implemented must require authentication upon booting into single-user mode and maintenance.'
  desc 'If the system allows a user to boot into single-user or maintenance mode without authentication, any user that invokes single-user or maintenance mode is granted privileged access to all system information.'
  desc 'check', 'Verify that the SUSE operating system has set an encrypted root password. 

Note: If the system does not use UEFI, this requirement is Not Applicable.

Check that the encrypted password is set for root with the following command:

> sudo cat /boot/efi/EFI/sles/grub.cfg | grep -i password 

password_pbkdf2 root grub.pbkdf2.sha512.10000.VeryLongString

If the root password entry does not begin with "password_pbkdf2", this is a finding.'
  desc 'fix', 'Note: If the system does not use UEFI, this requirement is Not Applicable.

Configure the SUSE operating system to encrypt the boot password.

Generate an encrypted (GRUB2) password for root with the following command:

> grub2-mkpasswd-pbkdf2
Enter Password:
Reenter Password:
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.MFU48934NJD84NF8NSD39993JDHF84NG

Using the hash from the output, modify the "/etc/grub.d/40_custom" file and add the following two lines to add a boot password for the root entry:

set superusers="root"
password_pbkdf2 root grub.pbkdf2.sha512.VeryLongString

Generate an updated "grub.conf" file with the new password using the following commands:

> sudo grub2-mkconfig --output=/tmp/grub2.cfg
> sudo mv /tmp/grub2.cfg /boot/efi/EFI/sles/grub.cfg'
  impact 0.7
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38008r618729_chk'
  tag severity: 'high'
  tag gid: 'V-234820'
  tag rid: 'SV-234820r622137_rule'
  tag stig_id: 'SLES-15-010200'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-37971r618730_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
