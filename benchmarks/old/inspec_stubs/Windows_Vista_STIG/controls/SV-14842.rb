control 'SV-14842' do
  title 'Hide Computer from the browse list.'
  desc 'This check verifies Windows Vista is configured to hide the computer from the browse list.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (Hidden) Hide Computer From the Browse List” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-14231'
  tag rid: 'SV-14842r1_rule'
  tag gtitle: 'Hide Computer'
  tag fix_id: 'F-13555r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
