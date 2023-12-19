control 'SV-25818' do
  title 'The system must be configured to force users to log off when their allowed logon hours expire.'
  desc 'Limiting logon hours can help protect data by only allowing access during specified times.  This setting controls whether or not users are forced to log off when their allowed logon hours expire.  If logon hours are set for users, then this must be enforced.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> Security Options.

If the value for "Network security: Force logoff when logon hours expire" is not set to "Enabled", this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> Security Options >> "Network security: Force logoff when logon hours expire" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-60795r2_chk'
  tag severity: 'medium'
  tag gid: 'V-3380'
  tag rid: 'SV-25818r2_rule'
  tag gtitle: 'Force Logoff When Logon Hours Expire'
  tag fix_id: 'F-65527r2_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
