control 'SV-14841' do
  title 'Audit policy using subcategories is enabled.'
  desc 'This policy setting allows administrators to enable the more precise auditing capabilities present in Windows Vista and later.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14230'
  tag rid: 'SV-14841r1_rule'
  tag gtitle: 'Audit Policy Subcategory Setting'
  tag fix_id: 'F-13554r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
