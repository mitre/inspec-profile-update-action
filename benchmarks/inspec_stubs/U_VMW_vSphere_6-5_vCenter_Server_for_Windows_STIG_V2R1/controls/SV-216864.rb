control 'SV-216864' do
  title 'The vCenter Server for Windows must limit the maximum number of failed login attempts to three.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. 

View the values for the lockout policies. 

The following lockout policy should be set at follows: 
Maximum number of failed login attempts: 3 

If this account lockout policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. Click "Edit". Set the Maximum number of failed login attempts to "3" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMW vSphere 6.5 vCenter Server for Windows'
  tag check_id: 'C-18095r366306_chk'
  tag severity: 'medium'
  tag gid: 'V-216864'
  tag rid: 'SV-216864r612237_rule'
  tag stig_id: 'VCWN-65-000045'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-18093r366307_fix'
  tag 'documentable'
  tag legacy: ['V-94793', 'SV-104623']
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
