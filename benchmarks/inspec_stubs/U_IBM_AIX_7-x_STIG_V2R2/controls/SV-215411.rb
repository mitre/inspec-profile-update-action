control 'SV-215411' do
  title 'AIX must not use removable media as the boot loader.'
  desc 'Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader.'
  desc 'check', 'Check the servers boot lists for the "normal", "service", "both", or "prevboot" modes by command:
# bootlist -m <mode> -o 

Ensure "hdisk{x}" is the only devices listed. If boot devices, such as "cd{x}", "fd{x}", "rmt{x}", or "ent{x}" are used, this is a finding.'
  desc 'fix', 'Configure the system to use a bootloader installed on fixed media, such as:
# bootlist -m normal hdisk0 
# bootlist -m service hdisk0'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16609r294684_chk'
  tag severity: 'medium'
  tag gid: 'V-215411'
  tag rid: 'SV-215411r508663_rule'
  tag stig_id: 'AIX7-00-003113'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16607r294685_fix'
  tag 'documentable'
  tag legacy: ['SV-101747', 'V-91649']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
