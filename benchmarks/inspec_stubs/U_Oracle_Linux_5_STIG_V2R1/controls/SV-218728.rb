control 'SV-218728' do
  title 'The systems boot loader configuration files must be owned by root.'
  desc "The system's boot loader configuration files are critical to the integrity of the system and must be protected.  Unauthorized modification of these files resulting from improper ownership could compromise the system's boot loader configuration."
  desc 'check', 'Check the ownership of the file.
# ls -lLd /boot/grub/grub.conf
If the owner of the file is not root, this is a finding.'
  desc 'fix', 'Change the ownership of the file.
# chown root /boot/grub/grub.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20203r562954_chk'
  tag severity: 'medium'
  tag gid: 'V-218728'
  tag rid: 'SV-218728r603259_rule'
  tag stig_id: 'GEN008760'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-20201r562955_fix'
  tag 'documentable'
  tag legacy: ['V-22586', 'SV-63089']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
