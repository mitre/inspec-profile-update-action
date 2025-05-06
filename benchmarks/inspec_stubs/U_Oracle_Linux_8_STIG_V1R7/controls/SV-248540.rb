control 'SV-248540' do
  title 'OL 8 operating systems booted with a BIOS must require authentication upon booting into single-user and maintenance modes.'
  desc 'If the system does not require valid authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for OL 8 and is designed to require a password to boot into single-user mode or modify the boot menu.'
  desc 'check', 'For systems that use UEFI, this is not applicable. 
 
Determine if an encrypted password is set for the grub superusers account. On systems that use a BIOS, use the following command: 
 
$ sudo grep -iw grub2_password /boot/grub2/user.cfg 
 
GRUB2_PASSWORD=grub.pbkdf2.sha512.[password_hash] 
 
If the grub superusers account password does not begin with "grub.pbkdf2.sha512", this is a finding.'
  desc 'fix', 'Configure the system to require a grub bootloader password for the grub superusers account with the grub2-setpassword command, which creates/overwrites the "/boot/grub2/user.cfg" file. 
 
Generate an encrypted grub2 password for the grub superusers account with the following command: 
 
$ sudo grub2-setpassword 
Enter password: 
Confirm password:'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51974r779184_chk'
  tag severity: 'high'
  tag gid: 'V-248540'
  tag rid: 'SV-248540r779186_rule'
  tag stig_id: 'OL08-00-010150'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-51928r779185_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
