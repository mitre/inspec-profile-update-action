control 'SV-29682' do
  title 'The built-in Microsoft password filter is not enabled.'
  desc 'The use of complex passwords increases their strength against guessing.  This policy setting configures the system to verify that newly-created passwords conform to the Windows password complexity policy.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> “Password must meet complexity requirements” to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-1150'
  tag rid: 'SV-29682r1_rule'
  tag gtitle: 'Microsoft Strong Password Filtering'
  tag fix_id: 'F-28809r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
end
