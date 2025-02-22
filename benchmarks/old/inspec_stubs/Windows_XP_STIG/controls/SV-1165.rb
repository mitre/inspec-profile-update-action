control 'SV-1165' do
  title 'The computer account password is prevented from being reset.'
  desc 'As a part of Windows security, computer account passwords are changed automatically.  Enabling this policy to disable automatic password changes can make the system more vulnerable to malicious access.  Frequent password changes can be a significant safeguard for your system.  If this policy is disabled, a new password for the computer account will be generated every week.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Domain Member: Disable Machine Account Password Changes” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-1165'
  tag rid: 'SV-1165r1_rule'
  tag gtitle: 'Computer Account Password Reset'
  tag fix_id: 'F-102r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
end
