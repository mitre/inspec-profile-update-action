control 'SV-203781' do
  title 'The operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created they do not have unnecessary access.'
  desc 'check', 'Verify the operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3906r375734_chk'
  tag severity: 'medium'
  tag gid: 'V-203781'
  tag rid: 'SV-203781r388482_rule'
  tag stig_id: 'SRG-OS-000480-GPOS-00228'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-3906r375735_fix'
  tag 'documentable'
  tag legacy: ['SV-70849', 'V-56589']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
