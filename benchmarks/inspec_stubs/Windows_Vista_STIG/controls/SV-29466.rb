control 'SV-29466' do
  title 'Secure Removable Media – CD-ROM'
  desc 'This check verifies that Windows is configured to not limit access to CD drives when a user is logged on locally per the FDCC.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Devices: Restrict CD-ROM access to locally logged-on user only” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-17373'
  tag rid: 'SV-29466r1_rule'
  tag gtitle: 'Secure Removable Media – CD-ROM'
  tag fix_id: 'F-27980r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
