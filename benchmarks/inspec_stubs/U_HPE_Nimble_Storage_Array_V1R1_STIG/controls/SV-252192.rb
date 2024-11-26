control 'SV-252192' do
  title 'The HPE Nimble must enforce password complexity by requiring that at least one lower-case character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'Type "userpolicy --info" and review output for line: "Minimum Lowercase characters". If it is 1 or more, this is not a finding.'
  desc 'fix', 'Set minimum number of lowercase characters to 1 by typing "userpolicy --edit --lower 1".'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55648r814054_chk'
  tag severity: 'medium'
  tag gid: 'V-252192'
  tag rid: 'SV-252192r814056_rule'
  tag stig_id: 'HPEN-NM-000070'
  tag gtitle: 'SRG-APP-000167-NDM-000255'
  tag fix_id: 'F-55598r814055_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
