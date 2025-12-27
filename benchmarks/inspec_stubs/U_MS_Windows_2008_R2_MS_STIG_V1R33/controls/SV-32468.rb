control 'SV-32468' do
  title 'The system will be configured to force users to log off when their allowed logon hours expire.'
  desc 'This setting controls whether or not users are forced to log off when their allowed logon hours expire.  If logon hours are set for users, then this should be enforced.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in. 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> Security Options. 

If the value for “Network security: Force logoff when logon hours expire” is not set to “Enabled”, then this is a finding.

This setting does not have a corresponding registry update.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network security: Force logoff when logon hours expire” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-32786r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3380'
  tag rid: 'SV-32468r1_rule'
  tag gtitle: 'Force Logoff When Logon Hours Expire'
  tag fix_id: 'F-28862r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
