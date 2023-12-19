control 'SV-221632' do
  title 'Splunk Enterprise must enforce a minimum 15-character password length for the account of last resort.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

In most enterprise environments, this requirement is usually mitigated by a properly configured external authentication system, like LDAP. Splunk local authentication takes precedence over other forms of authentication, and cannot be disabled. The mitigation settings in this requirement apply in the event a local account gets created, for example, an emergency account of last resort for recovery.'
  desc 'check', 'Select Settings >> Access Controls >> Password Policy Management and verify that Minimum characters is set to 15 or more.

If Minimum characters is less than 15, this is a finding.'
  desc 'fix', 'Select Settings >> Access Controls >>Password Policy Management and set Minimum characters to 15 or more.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23347r416353_chk'
  tag severity: 'medium'
  tag gid: 'V-221632'
  tag rid: 'SV-221632r879601_rule'
  tag stig_id: 'SPLK-CL-000360'
  tag gtitle: 'SRG-APP-000164-AU-002480'
  tag fix_id: 'F-23336r416354_fix'
  tag 'documentable'
  tag legacy: ['SV-111355', 'V-102411']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
