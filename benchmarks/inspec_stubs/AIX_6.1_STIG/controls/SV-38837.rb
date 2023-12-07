control 'SV-38837' do
  title 'The system must not use removable media as the boot loader.'
  desc 'Malicious users with removable boot media can gain access to a system configured to use removable media as the boot loader.'
  desc 'check', 'Check the servers boot lists for the normal, service, both, or prevboot modes.

# bootlist -m <mode> -o
Ensure hdisk{x} is the only devices listed.   If boot devices, such as cd{x},  fd{x}. rmt{x}, ent{x} are used,  this is a finding.'
  desc 'fix', 'Configure the system to use a bootloader installed on fixed media. 
# bootlist -m normal hdisk0
# bootlist -m service hdisk0'
  impact 0.7
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37099r1_chk'
  tag severity: 'high'
  tag gid: 'V-4247'
  tag rid: 'SV-38837r1_rule'
  tag stig_id: 'GEN008640'
  tag gtitle: 'GEN008640'
  tag fix_id: 'F-32369r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
