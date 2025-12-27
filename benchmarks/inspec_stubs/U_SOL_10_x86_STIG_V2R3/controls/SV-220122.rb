control 'SV-220122' do
  title 'The system must not use removable media as the boot loader.'
  desc 'Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader.'
  desc 'check', 'Ask the SA if the system uses removable media for the boot loader.  If it does, this is a finding.'
  desc 'fix', 'Configure the system to use a bootloader installed on fixed media.'
  impact 0.7
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21831r490390_chk'
  tag severity: 'high'
  tag gid: 'V-220122'
  tag rid: 'SV-220122r603266_rule'
  tag stig_id: 'GEN008640'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21830r490391_fix'
  tag 'documentable'
  tag legacy: ['V-4247', 'SV-41534']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
