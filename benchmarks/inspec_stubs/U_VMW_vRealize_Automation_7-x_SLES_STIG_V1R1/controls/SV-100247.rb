control 'SV-100247' do
  title 'The system boot loader configuration files must be owned by root.'
  desc "The system's boot loader configuration files are critical to the integrity of the system and must be protected. Unauthorized modification of these files resulting from improper ownership could compromise the system's boot loader configuration."
  desc 'check', 'Check /boot/grub/menu.lst ownership:

# stat /boot/grub/menu.lst

If the owner of the file is not "root", this is a finding.'
  desc 'fix', 'Change the ownership of the file:

# chown root /boot/grub/menu.lst'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89289r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89597'
  tag rid: 'SV-100247r1_rule'
  tag stig_id: 'VRAU-SL-000435'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-96339r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
