control 'SV-34585' do
  title 'The Windows dialog box title for the legal banner must be configured.'
  desc 'Failure to display the logon banner prior to a logon attempt will negate legal proceedings resulting from unauthorized access to system resources.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options “Interactive Logon: Message title for users attempting to log on” to “DoD Notice and Consent Banner”, “US Department of Defense Warning Statement”, or a site defined equivalent.  

If a site defined title is used, it can in no case contravene or modify the language of the banner text required in V-1089.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-26359'
  tag rid: 'SV-34585r2_rule'
  tag gtitle: 'Legal Banner Dialog Box Title'
  tag fix_id: 'F-36225r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECWM-1'
end
