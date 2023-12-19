control 'SV-26261' do
  title "The system's boot loader configuration files must be owned by root."
  desc "The system's boot loader configuration files are critical to the integrity of the system and must be protected.  Unauthorized modification of these files resulting from improper ownership could compromise the system's boot loader configuration."
  desc 'check', 'If the system does not use GRUB, this is not applicable.

Check the owner of the grub.conf file.
# ls -lL grub.conf
If the owner is not root, this is a finding.'
  desc 'fix', 'Change the owner of the grub.conf file to root.
# chown root grub.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29321r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22586'
  tag rid: 'SV-26261r1_rule'
  tag stig_id: 'GEN008760'
  tag gtitle: 'GEN008760'
  tag fix_id: 'F-26353r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
