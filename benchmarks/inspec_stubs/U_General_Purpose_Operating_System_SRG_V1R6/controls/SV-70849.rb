control 'SV-70849' do
  title 'The operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created they do not have unnecessary access.'
  desc 'check', 'Verify the operating system defines default permissions for all authenticated users in such a way that the user can only read and modify their own files. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57159r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56589'
  tag rid: 'SV-70849r1_rule'
  tag stig_id: 'SRG-OS-000480-GPOS-00228'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-61485r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
