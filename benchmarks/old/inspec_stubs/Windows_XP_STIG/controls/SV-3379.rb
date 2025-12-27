control 'SV-3379' do
  title 'The system is configured to store the LAN Manager hash of the password in the SAM.'
  desc 'This setting controls whether or not a LAN Manager hash of the password is stored in the SAM the next time the password is changed.  The LAN Manager hash is a weak encryption algorithm and there are several tools available that use this hash to retrieve account passwords.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network security: Do not store LAN Manager hash value on next password change” to “Enabled”.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag severity: 'high'
  tag gid: 'V-3379'
  tag rid: 'SV-3379r1_rule'
  tag gtitle: 'LAN Manager Hash stored'
  tag fix_id: 'F-141r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'IAIA-2, ECSC-1, IAIA-1'
end
