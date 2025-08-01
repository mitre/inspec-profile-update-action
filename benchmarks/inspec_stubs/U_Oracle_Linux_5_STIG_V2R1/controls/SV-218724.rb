control 'SV-218724' do
  title 'The system boot loader must require authentication.'
  desc "If the system's boot loader does not require authentication, users with console access to the system may be able to alter the system boot configuration or boot the system into single user or maintenance mode, which could result in Denial of Service or unauthorized privileged access to the system."
  desc 'check', 'Check the "/boot/grub/grub.conf" or "/boot/grub/menu.lst" files.
# more /boot/grub/menu.lst

Check for a password configuration line, such as:
password --md5 <password-hash>

This line should be just below the line beginning with "timeout". Please note <password-hash> will be replaced by the actual MD5 encrypted password. If the password line is not in either of the files, this is a finding.

For any bootloader other than GRUB which has been authorized, justified and documented for use on the system refer to the vendor documentation on password support. If the bootloader does not support encrypted passwords, this is a finding.'
  desc 'fix', 'The GRUB console boot loader can be configured to use an MD5 encrypted password by adding password --md5 password-hash to the "/boot/grub/grub.conf" file. Use "/sbin/grub-md5-crypt" to generate MD5 passwords from the command line.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20199r556589_chk'
  tag severity: 'high'
  tag gid: 'V-218724'
  tag rid: 'SV-218724r603259_rule'
  tag stig_id: 'GEN008700'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-20197r556590_fix'
  tag 'documentable'
  tag legacy: ['V-4249', 'SV-63105']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
