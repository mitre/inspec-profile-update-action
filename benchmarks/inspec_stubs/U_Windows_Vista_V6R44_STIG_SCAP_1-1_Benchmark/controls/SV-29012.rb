control 'SV-29012' do
  title 'The Send download LanMan compatible password option is not set to Send NTLMv2 response only\\refuse LM.'
  desc 'The Kerberos v5 authentication protocol is the default for authentication of users who are logging on to domain accounts.  NTLM is retained in later Windows versions  for compatibility with clients and servers that are running earlier versions of Windows.  It is also used to authenticate logons to stand-alone computers that are running later versions.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network security: LAN Manager authentication level” to at least “Send NTLMv2 response only\\refuse LM”.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-1153'
  tag rid: 'SV-29012r1_rule'
  tag gtitle: 'LanMan Authentication Level'
  tag fix_id: 'F-91r1_fix'
  tag potential_impacts: 'Setting this to the required setting may prevent authentication with older Operating Systems and break some applications.'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
