control 'SV-3376' do
  title 'The system is configured to permit storage of credentials or .NET Passports.'
  desc 'This setting controls the storage of authentication credentials or .NET passports on the local system.  Such credentials should never be stored on the local machine as that may lead to account compromise.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Do not allow storage of credentials or .NET passports for network authentication” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3376'
  tag rid: 'SV-3376r1_rule'
  tag gtitle: 'Storage of Passwords and Credentials'
  tag fix_id: 'F-132r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
