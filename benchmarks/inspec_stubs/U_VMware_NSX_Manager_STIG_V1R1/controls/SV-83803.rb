control 'SV-83803' do
  title 'The NSX vCenter must automatically lock the account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are exceeded.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify vCenter Server is configured to a limit of three consecutive invalid logon attempts by a Single Sign-On user and Active Directory user during a 15-minute time period.

Log on to vSphere Web Client with credentials authorized for administration, navigate and select Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. 

View the values for the lockout policies.

The following lockout policies must be set as follows:

Maximum number of failed login attempts: 3
Time interval between failures: 900 seconds
Unlock time: 0

If any of these account lockout policies are not configured in Single Sign-On and Active Directory as stated, this is a finding.'
  desc 'fix', 'Change vCenter Server configuration to a limit of three consecutive invalid logon attempts by a Single Sign-On and Active Directory user during a 15-minute time period.

Log on to vSphere Web Client with credentials authorized for administration, navigate and select Administration >> Single Sign-On >> Configuration >> Policies >> Lockout Policy. View the values for the lockout policies.

The following lockout policies must be set as follows:

Maximum number of failed login attempts: 3
Time interval between failures: 900 seconds
Unlock time: 0

Ensure Active Directory is configured with these account lockout settings as stated.'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69639r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69199'
  tag rid: 'SV-83803r1_rule'
  tag stig_id: 'VNSX-ND-000094'
  tag gtitle: 'SRG-APP-000345-NDM-000290'
  tag fix_id: 'F-75385r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']
end
