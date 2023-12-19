control 'SV-29023' do
  title 'The Recovery Console option is set to permit automatic logon to the system.'
  desc 'This is a Category 1 finding because if this option is set, the Recovery Console does not require you to provide a password and will automatically log on to the system, giving Administrator access to system files.

By default, the Recovery Console requires you to provide the password for the Administrator account before accessing the system.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Recovery Console: Allow automatic administrative logon” to “Disabled”.'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-1159'
  tag rid: 'SV-29023r1_rule'
  tag gtitle: 'Recovery Console - Automatic Logon'
  tag fix_id: 'F-28813r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
