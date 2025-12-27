control 'SV-218725' do
  title 'The system boot loader must protect passwords using an MD5 or stronger cryptographic hash.'
  desc 'If system boot loader passwords are compromised, users with console access to the system may be able to alter the system boot configuration or boot the system into single user or maintenance mode, which could result in Denial of Service or unauthorized privileged access to the system.'
  desc 'check', 'Check GRUB for password configuration.

Procedure:
Check the /boot/grub/grub.conf or /boot/grub/menu.lst files.
# grep "password" /boot/grub/grub.conf /boot/grub/menu.lst

Check for a password configuration line, such as:
password --md5 <password-hash>

If the boot loader passwords are not protected using an MD5 hash or stronger, this is a finding.'
  desc 'fix', "Consult vendor documentation for procedures concerning the system's boot loader.  Configure the boot loader to hash boot loader passwords using MD5 or a stronger hash."
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20200r556592_chk'
  tag severity: 'medium'
  tag gid: 'V-218725'
  tag rid: 'SV-218725r603259_rule'
  tag stig_id: 'GEN008710'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-20198r556593_fix'
  tag 'documentable'
  tag legacy: ['V-24624', 'SV-63097']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
