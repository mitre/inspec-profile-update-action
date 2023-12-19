control 'SV-217145' do
  title 'SUSE operating systems with Unified Extensible Firmware Interface (UEFI) implemented must require authentication upon booting into single-user mode and maintenance.'
  desc 'If the system allows a user to boot into single-user or maintenance mode without authentication, any user that invokes single-user or maintenance mode is granted privileged access to all system information.

If the system is running in EFI mode, SLES 12 by default will use GRUB 2 EFI as the boot loader.'
  desc 'check', 'Verify that the SUSE operating system has set an encrypted boot password. 

Note: If the system does not use Unified Extensible Firmware Interface (UEFI) this requirement is Not Applicable.

Check that the encrypted password is set for a boot user with the following command:

# sudo cat /boot/efi/EFI/sles/grub.cfg | grep -i password 

password_pbkdf2 boot grub.pbkdf2.sha512.10000.VeryLongString

If the boot user password entry does not begin with "password_pbkdf2", this is a finding.'
  desc 'fix', 'Note: If the system does not use UEFI, this requirement is Not Applicable.

Configure the SUSE operating system to encrypt the boot password.

Generate an encrypted (GRUB 2) password for a boot user with the following command:

# sudo grub2-mkpasswd-pbkdf2
Enter Password:
Reenter Password:
PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.MFU48934NJD84NF8NSD39993JDHF84NG

Using the hash from the output, modify the "/etc/grub.d/40_custom" file with the following command to add a boot password for the root entry:

# cat << EOF
set superusers="boot"
password_pbkdf2 boot grub.pbkdf2.sha512.VeryLongString
EOF

Generate an updated "grub.conf" file with the new password using the following commands:

# sudo grub2-mkconfig --output=/tmp/grub2.cfg
# sudo mv /tmp/grub2.cfg /boot/efi/EFI/sles/grub.cfg'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18373r369591_chk'
  tag severity: 'medium'
  tag gid: 'V-217145'
  tag rid: 'SV-217145r603262_rule'
  tag stig_id: 'SLES-12-010440'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-18371r369592_fix'
  tag 'documentable'
  tag legacy: ['SV-91841', 'V-77145']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
