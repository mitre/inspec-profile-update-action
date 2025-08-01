control 'SV-246851' do
  title 'The HYCU server must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.

'
  desc 'check', 'Log on to the HYCU VM console. Check for the value of the "minlen" option in "/etc/security/pwquality.conf" with the following command:
grep minclass /etc/security/pwquality.conf 

If the minclass value is not set to "5", this is a finding.'
  desc 'fix', 'Configure the operating system to enforce a minimum class setting.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):
minclass = 5'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50283r768215_chk'
  tag severity: 'medium'
  tag gid: 'V-246851'
  tag rid: 'SV-246851r768217_rule'
  tag stig_id: 'HYCU-IA-000003'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-50237r768216_fix'
  tag satisfies: ['SRG-APP-000166-NDM-000254', 'SRG-APP-000167-NDM-000255', 'SRG-APP-000168-NDM-000256', 'SRG-APP-000169-NDM-000257']
  tag 'documentable'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000205', 'CCI-001619']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)']
end
