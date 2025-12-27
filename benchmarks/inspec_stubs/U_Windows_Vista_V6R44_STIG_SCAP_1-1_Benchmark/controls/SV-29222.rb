control 'SV-29222' do
  title 'The default permissions of Global system objects are not increased.'
  desc 'Windows system maintains a global list of shared system resources such as DOS device names, mutexes, and semaphores. Each type of object is created with a default DACL that specifies who can access the objects with what permissions. If this policy is enabled, the default DACL is stronger, allowing non-admin users to read shared objects, but not modify shared objects that they did not create.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “System Objects: Strengthen default permissions of internal system objects (e.g. Symbolic links)” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-1173'
  tag rid: 'SV-29222r1_rule'
  tag gtitle: 'Global System Objects Permission Strength'
  tag fix_id: 'F-28815r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
