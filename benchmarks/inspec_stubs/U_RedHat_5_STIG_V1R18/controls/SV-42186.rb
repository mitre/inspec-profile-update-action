control 'SV-42186' do
  title 'For systems capable of using GRUB, the system must be configured with GRUB as the default boot loader unless another boot loader has been authorized, justified, and documented using site-defined procedures.'
  desc 'GRUB is a versatile boot loader used by several platforms that can provide authentication for access to the system or boot loader.'
  desc 'check', 'Determine if the system uses the GRUB boot loader;

# ls -l /boot/grub/grub.conf

If no grub.conf file exists, and the bootloader on the system has not been authorized, justified, and documented, this is a finding.'
  desc 'fix', 'Configure the system to use the GRUB bootloader or document, justify, and authorize the alternate bootloader.'
  impact 0.7
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-40580r1_chk'
  tag severity: 'high'
  tag gid: 'V-4248'
  tag rid: 'SV-42186r1_rule'
  tag stig_id: 'GEN008660'
  tag gtitle: 'GEN008660'
  tag fix_id: 'F-35823r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
