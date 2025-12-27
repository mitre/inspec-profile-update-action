control 'SV-216865' do
  title 'The vCenter Server for Windows must set the interval for counting failed login attempts to at least 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. 

View the values for the lockout policies. 

The following lockout policy should be set at follows: 
Time interval between failures: 900 seconds 

If this lockout policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. Click "Edit". Set the Time interval between failures to "900" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18096r366309_chk'
  tag severity: 'medium'
  tag gid: 'V-216865'
  tag rid: 'SV-216865r612237_rule'
  tag stig_id: 'VCWN-65-000046'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-18094r366310_fix'
  tag 'documentable'
  tag legacy: ['SV-104625', 'V-94795']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
