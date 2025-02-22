control 'SV-220101' do
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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21810r489925_chk'
  tag severity: 'medium'
  tag gid: 'V-220101'
  tag rid: 'SV-220101r603266_rule'
  tag stig_id: 'GEN004580'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21809r489926_fix'
  tag 'documentable'
  tag legacy: ['V-4385', 'SV-39827']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
