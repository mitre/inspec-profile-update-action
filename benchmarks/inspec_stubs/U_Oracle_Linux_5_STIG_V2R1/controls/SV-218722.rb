control 'SV-218722' do
  title 'For systems capable of using GRUB, the system must be configured with GRUB as the default boot loader unless another boot loader has been authorized, justified, and documented using site-defined procedures.'
  desc 'GRUB is a versatile boot loader used by several platforms that can provide authentication for access to the system or boot loader.'
  desc 'check', 'Determine if the system uses the GRUB boot loader;

# ls -l /boot/grub/grub.conf

If no grub.conf file exists, and the bootloader on the system has not been authorized, justified, and documented, this is a finding.'
  desc 'fix', 'Configure the system to use the GRUB bootloader or document, justify, and authorize the alternate bootloader.'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20197r556583_chk'
  tag severity: 'high'
  tag gid: 'V-218722'
  tag rid: 'SV-218722r603259_rule'
  tag stig_id: 'GEN008660'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20195r556584_fix'
  tag 'documentable'
  tag legacy: ['V-4248', 'SV-63115']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
