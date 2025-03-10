control 'SV-216866' do
  title 'The vCenter Server for Windows must require an administrator to unlock an account locked due to excessive login failures.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. 

View the values for the lockout policies. 

The following lockout policy should be set at follows: 
Unlock time: 0 

If this account lockout policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. Click "Edit". Set the Unlock time to "0" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18097r366312_chk'
  tag severity: 'medium'
  tag gid: 'V-216866'
  tag rid: 'SV-216866r612237_rule'
  tag stig_id: 'VCWN-65-000047'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-18095r366313_fix'
  tag 'documentable'
  tag legacy: ['SV-104627', 'V-94797']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
