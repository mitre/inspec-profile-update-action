control 'SV-37942' do
  title "The system's boot loader configuration file(s) must have mode 0600 or less permissive."
  desc 'File permissions greater than 0600 on boot loader configuration files could allow an unauthorized user to view or modify sensitive information pertaining to system boot instructions.'
  desc 'fix', 'Change the mode of the grub.conf file to 0600.

# chmod 0600 /boot/grub/grub.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-4250'
  tag rid: 'SV-37942r1_rule'
  tag stig_id: 'GEN008720'
  tag gtitle: 'GEN008720'
  tag fix_id: 'F-32433r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
