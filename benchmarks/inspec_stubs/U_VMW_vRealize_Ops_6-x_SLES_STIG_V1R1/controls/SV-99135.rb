control 'SV-99135' do
  title 'The SLES for the vRealize boot loader configuration files must be owned by root.'
  desc "The SLES for vRealize’s boot loader configuration files are critical to the integrity of the system and must be protected. Unauthorized modification of these files resulting from improper ownership could compromise the system's boot loader configuration."
  desc 'check', 'Check "/boot/grub/menu.lst" file ownership:

# stat /boot/grub/menu.lst

If the owner of the file is not "root", this is a finding.'
  desc 'fix', 'Change the ownership of the "/boot/grub/menu.lst" file:

# chown root /boot/grub/menu.lst'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88177r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88485'
  tag rid: 'SV-99135r1_rule'
  tag stig_id: 'VROM-SL-000430'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-95227r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
