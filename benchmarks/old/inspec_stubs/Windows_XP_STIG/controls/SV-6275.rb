control 'SV-6275' do
  title 'Unauthorized registry paths are remotely accessible.'
  desc 'This is a Category 1 finding because it could give unauthorized individuals access to the Registry.  
It controls which registry paths are accessible from a remote computer.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Remotely accessible registry paths” as defined in the Check section.'
  impact 0.7
  ref 'DPMS Target Windows XP'
  tag severity: 'high'
  tag gid: 'V-3339'
  tag rid: 'SV-6275r1_rule'
  tag gtitle: 'Remotely Accessible Registry Paths'
  tag fix_id: 'F-28869r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-2, ECCD-1'
end
