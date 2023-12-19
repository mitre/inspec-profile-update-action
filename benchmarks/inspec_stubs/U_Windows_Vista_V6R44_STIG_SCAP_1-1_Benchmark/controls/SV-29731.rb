control 'SV-29731' do
  title 'Unauthorized registry paths and sub-paths are remotely accessible.'
  desc 'The registry is a database for computer configuration information, much of which is sensitive. An attacker could use this to facilitate unauthorized activities. To reduce the risk of this happening, it is also lowered by the fact that the default ACLs assigned throughout the registry are fairly restrictive and they help to protect it from access by unauthorized users.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Remotely accessible registry paths and sub-paths” as specified in the Check section.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-4443'
  tag rid: 'SV-29731r1_rule'
  tag gtitle: 'Remotely Accessible Registry Paths and Sub-Paths'
  tag fix_id: 'F-5739r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
