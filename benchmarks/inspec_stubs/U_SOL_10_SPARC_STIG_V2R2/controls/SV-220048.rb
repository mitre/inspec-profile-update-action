control 'SV-220048' do
  title 'The system must not use .forward files.'
  desc 'The .forward file allows users to automatically forward mail to another system. Use of .forward files could allow the unauthorized forwarding of mail and could potentially create mail loops which could degrade system performance.'
  desc 'check', 'Search for any .forward files on the system.

# find / -name .forward -print

This is considered a finding if any .forward files are found on the system.'
  desc 'fix', 'Remove .forward files from the system. 

# rm .forward

Update the sendmail.cf file to ignore .forward files by adding 
ForwardPath="".'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21757r485138_chk'
  tag severity: 'medium'
  tag gid: 'V-220048'
  tag rid: 'SV-220048r603265_rule'
  tag stig_id: 'GEN004580'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21756r485139_fix'
  tag 'documentable'
  tag legacy: ['V-4385', 'SV-39827']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
