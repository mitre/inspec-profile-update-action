control 'SV-29009' do
  title 'Print driver installation privilege is not restricted to administrators.'
  desc 'By default, the print spooler allows any user to add and to delete printer drivers on the local system.  This capability should be restricted to authorized personnel.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Devices: Prevent users from installing printer drivers” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-1151'
  tag rid: 'SV-29009r1_rule'
  tag gtitle: 'Secure Print Driver Installation'
  tag fix_id: 'F-83r1_fix'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
