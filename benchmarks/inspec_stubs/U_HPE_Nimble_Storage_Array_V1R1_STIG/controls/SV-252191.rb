control 'SV-252191' do
  title 'The HPE Nimble must enforce password complexity by requiring that at least one upper-case character be used.'
  desc 'Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Type "userpolicy --info" and review output for line: "Minimum Uppercase characters". If it is 1 or more, this is not a finding.'
  desc 'fix', 'Set minimum number of uppercase characters to 1 by typing "userpolicy --edit --upper 1".'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55647r814051_chk'
  tag severity: 'medium'
  tag gid: 'V-252191'
  tag rid: 'SV-252191r814053_rule'
  tag stig_id: 'HPEN-NM-000060'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag fix_id: 'F-55597r814052_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
