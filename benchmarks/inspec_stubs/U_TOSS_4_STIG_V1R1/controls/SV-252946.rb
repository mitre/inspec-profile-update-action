control 'SV-252946' do
  title 'TOSS must enforce the limit of five consecutive invalid logon attempts by a user during a 15-minute time period.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.'
  desc 'check', 'Verify the "/etc/security/faillock.conf" file is configured to lock an account after three unsuccessful logon attempts within 15 minutes:

$ sudo grep -e "deny =" -e "fail_interval =" /etc/security/faillock.conf
deny = 3
fail_interval = 900

If the "deny" option is set to "0", more than "3", is missing, or is commented out, this is a finding.
If the "fail_interval" option is set to less than "900", is missing, or is commented out, this is a finding.

Note: If the System Administrator demonstrates the use of an approved centralized account management method that locks an account after three unsuccessful logon attempts within a period of 15 minutes, this requirement is Not Applicable.'
  desc 'fix', 'Configure the operating system to lock an account when three unsuccessful logon attempts occur in 15 minutes.

Add/Modify the "/etc/security/faillock.conf" file to match the following lines:

deny = 3
fail_interval = 900'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56399r824160_chk'
  tag severity: 'medium'
  tag gid: 'V-252946'
  tag rid: 'SV-252946r824162_rule'
  tag stig_id: 'TOSS-04-020000'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-56349r824161_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
