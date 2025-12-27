control 'SV-219180' do
  title 'The Ubuntu operating system must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify that the Ubuntu operating system prevents passwords from being reused for a minimum of five generations by running the following command:

# grep -i remember /etc/pam.d/common-password

password [success=1 default=ignore] pam_unix.so sha512 shadow remember=5 rounds=5000

If the "remember" parameter value is not greater than or equal to 5, commented out, or not set at all this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system prevents passwords from being reused for a minimum of five generations.

Add, or modify the "remember" parameter value to the following line in "/etc/pam.d/common-password" file:

password [success=1 default=ignore] pam_unix.so sha512 shadow remember=5 rounds=5000'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20905r304868_chk'
  tag severity: 'low'
  tag gid: 'V-219180'
  tag rid: 'SV-219180r610963_rule'
  tag stig_id: 'UBTU-18-010108'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-20904r304869_fix'
  tag 'documentable'
  tag legacy: ['V-100587', 'SV-109691']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
