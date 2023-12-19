control 'SV-15089' do
  title 'Unauthorized named pipes are accessible with anonymous credentials.'
  desc 'This is a Category 1 finding because the potential for gaining unauthorized system access.  Pipes are internal system communications processes.  They are identified internally by ID numbers that vary between systems.  To make access to these processes easier, these pipes are given names that do not vary between systems.  This setting controls which of these pipes anonymous users may access.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Named pipes that can be accessed anonymously” as defined in the Check section.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-3338'
  tag rid: 'SV-15089r1_rule'
  tag gtitle: 'Anonymous Access to Named Pipes'
  tag fix_id: 'F-28868r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
