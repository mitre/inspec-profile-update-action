control 'SV-1157' do
  title 'The Smart Card removal option is set to take no action.'
  desc 'Determines what should happen when the smart card for a logged-on user is removed from the smart card reader.

The options are:
- No Action
- Lock Workstation
- Force Logoff'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Interactive logon: Smart card removal behavior” to  “Lock Workstation” or “Force Logoff”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-1157'
  tag rid: 'SV-1157r1_rule'
  tag gtitle: 'Smart Card Removal Option'
  tag fix_id: 'F-105r1_fix'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
