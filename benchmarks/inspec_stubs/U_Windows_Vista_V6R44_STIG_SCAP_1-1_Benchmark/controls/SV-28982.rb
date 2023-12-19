control 'SV-28982' do
  title 'Anonymous shares are not restricted.'
  desc 'This is a Category 1 finding because it allows anonymous logon users (null session connections) to list all account names and enumerate all shared resources, thus providing a map of potential points to attack the system.'
  desc 'fix', 'Configure the policy values for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Network access: Do not allow anonymous enumeration of SAM accounts” and “Network access: Do not allow anonymous enumeration of SAM accounts and shares” to “Enabled".'
  impact 0.7
  ref 'DPMS Target Windows Vista'
  tag severity: 'high'
  tag gid: 'V-1093'
  tag rid: 'SV-28982r1_rule'
  tag gtitle: 'Anonymous shares are not restricted'
  tag fix_id: 'F-28805r1_fix'
  tag potential_impacts: 'In a mixed Windows environment this setting may cause systems with down-level operating systems to fail to authenticate, may prevent their users from changing their passwords, and may cause problems with managing printers and spools.'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
