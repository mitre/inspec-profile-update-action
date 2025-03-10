control 'SV-34590' do
  title 'The Windows dialog box title for the legal banner must be configured.'
  desc 'Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options “Interactive Logon: Message title for users attempting to log on” to “DoD Notice and Consent Banner”, “US Department of Defense Warning Statement”, or a site defined equivalent.  

If a site defined title is used, it can in no case contravene or modify the language of the banner text required in V-1089.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-26359'
  tag rid: 'SV-34590r2_rule'
  tag gtitle: 'Legal Banner Dialog Box Title'
  tag fix_id: 'F-36225r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3']
end
