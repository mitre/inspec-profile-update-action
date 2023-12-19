control 'SV-54982' do
  title 'The system must not use removable media as the boot loader.'
  desc 'Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader.'
  desc 'check', 'Verify whether the system BIOS or controller allows removable media for the boot loader.  If it does, this is a finding.'
  desc 'fix', 'Configure the system BIOS or controller to use a boot loader installed on fixed media.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-48724r2_chk'
  tag severity: 'high'
  tag gid: 'V-36664'
  tag rid: 'SV-54982r1_rule'
  tag stig_id: 'WIN00-000012'
  tag gtitle: 'WIN00-000012'
  tag fix_id: 'F-47865r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
