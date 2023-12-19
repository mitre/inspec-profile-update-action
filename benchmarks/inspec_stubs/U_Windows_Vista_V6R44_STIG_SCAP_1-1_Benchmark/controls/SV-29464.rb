control 'SV-29464' do
  title 'Remove Software Certificate Installation Files'
  desc 'This check verifies that software certificate installation files have been removed from a system.'
  desc 'fix', 'Remove any certificate installation files found on a system.

Note:  This does not apply to server-based applications that have a requirement for .p12 certificate files (e.g., Oracle Wallet Manager)'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15823'
  tag rid: 'SV-29464r1_rule'
  tag gtitle: 'Software Certificate Installation Files'
  tag fix_id: 'F-15775r1_fix'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
