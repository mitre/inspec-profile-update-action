control 'SV-219166' do
  title 'The Ubuntu operating system must be configured so that three consecutive invalid logon attempts by a user automatically locks the account until released by an administrator.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-force attacks, is reduced. Limits are imposed by locking the account.
'
  desc 'check', 'Check that Ubuntu operating system locks an account after three unsuccessful login attempts with following command:

# grep pam_tally2 /etc/pam.d/common-auth 

auth required pam_tally2.so onerr=fail deny=3

If no line is returned or the line is commented out, this is a finding.
If the line is missing "onerr=fail", this is a finding.
If the line has "deny" set to a value more than 3, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to lock an account after three unsuccessful login attempts. 

Edit the /etc/pam.d/common-auth file. The pam_tally2.so entry must be placed at the top of the "auth" stack. So add the following line before the first "auth" entry in the file.

auth required pam_tally2.so onerr=fail deny=3'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20891r569453_chk'
  tag severity: 'medium'
  tag gid: 'V-219166'
  tag rid: 'SV-219166r610963_rule'
  tag stig_id: 'UBTU-18-010033'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-20890r569454_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128']
  tag 'documentable'
  tag legacy: ['SV-109663', 'V-100559']
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
