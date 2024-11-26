control 'SV-29682' do
  title 'The built-in Microsoft password filter is not enabled.'
  desc 'The use of complex passwords increases their strength against guessing.  This policy setting configures the system to verify that newly-created passwords conform to the Windows password complexity policy.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies -> Password Policy.

If the value for “Password must meet complexity requirements” is not set to "Enabled", then this is a finding.

Note: If the site is using a password filter that requires this setting be set to “Disabled” for the filter code to be used, then this would not be considered a finding.  If this setting does not affect the use of an external password filter, it will be enabled for fall-back purposes.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> “Password must meet complexity requirements” to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-32937r1_chk'
  tag severity: 'low'
  tag gid: 'V-1150'
  tag rid: 'SV-29682r1_rule'
  tag gtitle: 'Microsoft Strong Password Filtering'
  tag fix_id: 'F-28809r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
end
