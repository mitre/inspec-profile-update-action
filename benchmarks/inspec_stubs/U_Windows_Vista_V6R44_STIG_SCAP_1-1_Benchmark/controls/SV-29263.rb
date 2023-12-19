control 'SV-29263' do
  title 'The system is configured to give anonymous users Everyone rights.'
  desc 'This setting helps define the permissions that anonymous users have.  If this setting is enabled then anonymous users have the same rights and permissions as the built-in Everyone group.  Anonymous users should not have these permissions or rights.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Let everyone permissions apply to anonymous users” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-3377'
  tag rid: 'SV-29263r1_rule'
  tag gtitle: 'Everyone Anonymous rights'
  tag fix_id: 'F-133r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
