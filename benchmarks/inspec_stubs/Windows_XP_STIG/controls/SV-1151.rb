control 'SV-1151' do
  title 'Print driver installation privilege is not restricted to administrators.'
  desc 'By default, the print spooler allows any user to add and to delete printer drivers on the local system.  This capability should be restricted to authorized personnel.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Devices: Prevent users from installing printer drivers” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-1151'
  tag rid: 'SV-1151r1_rule'
  tag gtitle: 'Secure Print Driver Installation'
  tag fix_id: 'F-83r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECLP-1'
end
