control 'SV-3374' do
  title 'The system is not configured to require a strong session key.'
  desc 'This setting controls the required strength of a session key.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Domain Member: Require Strong (Windows 2000 or Later) Session Key” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3374'
  tag rid: 'SV-3374r1_rule'
  tag gtitle: 'Strong Session Key'
  tag fix_id: 'F-5801r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Setting this value in a domain containing Windows NT or older operating systems will prevent those systems from authenticating.  This setting can also prevent a system from being joined to a domain.'
  tag third_party_tools: 'HK'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1'
end
