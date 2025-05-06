control 'SV-243105' do
  title 'The vCenter Server must set the interval for counting failed login attempts to at least 15 minutes.'
  desc 'By limiting the number of failed login attempts within a specified time period, the risk of unauthorized access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. 

View the values for the lockout policies. 

The following lockout policy should be set at follows: 

Time interval between failures: 900 seconds 

If this lockout policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. 

Click "Edit". 

Set the "Time interval between failures" to "900" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46380r719556_chk'
  tag severity: 'medium'
  tag gid: 'V-243105'
  tag rid: 'SV-243105r719558_rule'
  tag stig_id: 'VCTR-67-000046'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-46337r719557_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
