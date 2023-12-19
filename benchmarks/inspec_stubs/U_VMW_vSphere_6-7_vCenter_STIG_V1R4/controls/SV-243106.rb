control 'SV-243106' do
  title 'The vCenter Server must require an administrator to unlock an account locked due to excessive login failures.'
  desc 'By requiring that SSO accounts be unlocked manually, the risk of unauthorized access via user password guessing, otherwise known as brute forcing, is reduced. When the account unlock time is set to zero, once an account is locked it can only be unlocked manually by an administrator.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. 

View the values for the lockout policies. 

The following lockout policy should be set at follows: 

Unlock time: 0 

If this account lockout policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. 

Click "Edit". 

Set the "Unlock time" to "0" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46381r719559_chk'
  tag severity: 'medium'
  tag gid: 'V-243106'
  tag rid: 'SV-243106r879722_rule'
  tag stig_id: 'VCTR-67-000047'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-46338r719560_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
