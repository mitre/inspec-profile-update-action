control 'SV-29269' do
  title 'The system must be configured to prevent the storage of the LAN Manager hash of passwords.'
  desc 'The LAN Manager hash uses a weak encryption algorithm.  Account passwords can be retrieved from this hash using available tools.  This setting controls whether or not a LAN Manager hash of the password is stored in the SAM the next time the password is changed.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "Network security: Do not store LAN Manager hash value on next password change" to "Enabled".'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-3379'
  tag rid: 'SV-29269r2_rule'
  tag gtitle: 'LAN Manager Hash stored'
  tag fix_id: 'F-63897r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
