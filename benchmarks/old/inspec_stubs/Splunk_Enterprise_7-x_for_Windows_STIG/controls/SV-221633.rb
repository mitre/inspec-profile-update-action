control 'SV-221633' do
  title 'Splunk Enterprise must enforce password complexity for the account of last resort by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.

In most enterprise environments, this requirement is usually mitigated by a properly configured external authentication system, like LDAP. Splunk local authentication takes precedence over other forms of authentication, and cannot be disabled. The mitigation settings in this requirement apply in the event a local account gets created, for example, an emergency account of last resort for recovery.'
  desc 'check', 'Select Settings >> Access Controls >> Password Policy Management and verify that Special character is set to greater than 0.

If Special character is set to 0, this is a finding.'
  desc 'fix', 'Select Settings >> Access Controls >> Password Policy Management and set Special character to greater than 0.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23348r416356_chk'
  tag severity: 'low'
  tag gid: 'V-221633'
  tag rid: 'SV-221633r879606_rule'
  tag stig_id: 'SPLK-CL-000370'
  tag gtitle: 'SRG-APP-000169-AU-002520'
  tag fix_id: 'F-23337r416357_fix'
  tag 'documentable'
  tag legacy: ['SV-111357', 'V-102413']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
