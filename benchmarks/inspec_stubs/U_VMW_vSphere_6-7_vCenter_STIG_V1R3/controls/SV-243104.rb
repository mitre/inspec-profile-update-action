control 'SV-243104' do
  title 'The vCenter Server must limit the maximum number of failed login attempts to three.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. 

View the values for the lockout policies. 

The following lockout policy should be set at follows: 

Maximum number of failed login attempts: 3 

If this account lockout policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy.

Click "Edit". 

Set the "Maximum number of failed login attempts" to "3" and click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 vCenter'
  tag check_id: 'C-46379r719553_chk'
  tag severity: 'medium'
  tag gid: 'V-243104'
  tag rid: 'SV-243104r850126_rule'
  tag stig_id: 'VCTR-67-000045'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-46336r719554_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
