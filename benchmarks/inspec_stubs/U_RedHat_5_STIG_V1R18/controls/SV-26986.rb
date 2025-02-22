control 'SV-26986' do
  title "The system's boot loader configuration files must be owned by root."
  desc "The system's boot loader configuration files are critical to the integrity of the system and must be protected.  Unauthorized modification of these files resulting from improper ownership could compromise the system's boot loader configuration."
  desc 'check', 'Check the ownership of the file.
# ls -lLd /boot/grub/grub.conf
If the owner of the file is not root, this is a finding.'
  desc 'fix', 'Change the ownership of the file.
# chown root /boot/grub/grub.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-37231r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22586'
  tag rid: 'SV-26986r1_rule'
  tag stig_id: 'GEN008760'
  tag gtitle: 'GEN008760'
  tag fix_id: 'F-32438r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
