control 'SV-16650' do
  title 'Search – Encrypted Files Indexing'
  desc 'This check verifies that encrypted files are not indexed.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Search “Allow indexing of encrypted files” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15711'
  tag rid: 'SV-16650r1_rule'
  tag gtitle: 'Search – Encrypted Files Indexing'
  tag fix_id: 'F-15603r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
