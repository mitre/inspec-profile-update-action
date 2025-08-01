control 'SV-78515' do
  title 'The system must limit the maximum number of failed login attempts to three.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy.  View the values for the lockout policies.

The following lockout policy should be set at follows:

Maximum number of failed login attempts: 3

If this account lockout policy is not configured as stated, this is a finding.'
  desc 'fix', 'From the vSphere Web Client go to Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy.  Click Edit. Set the Maximum number of failed login attempts to 3 and click OK.'
  impact 0.5
  ref 'DPMS Target vCenter Server 6.0'
  tag check_id: 'C-64777r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64025'
  tag rid: 'SV-78515r1_rule'
  tag stig_id: 'VCWN-06-000045'
  tag gtitle: 'SRG-APP-000345'
  tag fix_id: 'F-69955r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
