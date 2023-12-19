control 'SV-221631' do
  title 'Splunk Enterprise must enforce password complexity for the account of last resort by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

In most enterprise environments, this requirement is usually mitigated by a properly configured external authentication system, like LDAP. Splunk local authentication takes precedence over other forms of authentication, and cannot be disabled. The mitigation settings in this requirement apply in the event a local account gets created, for example, an emergency account of last resort for recovery.'
  desc 'check', 'Select Settings >> Access Controls >> Password Policy Management and verify that Numeral is set to greater than 0.

If Numeral is set to 0, this is a finding.'
  desc 'fix', 'Select Settings >> Access Controls >> Password Policy Management and set Numeral to greater than 0.'
  impact 0.3
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23346r416350_chk'
  tag severity: 'low'
  tag gid: 'V-221631'
  tag rid: 'SV-221631r879605_rule'
  tag stig_id: 'SPLK-CL-000350'
  tag gtitle: 'SRG-APP-000168-AU-002510'
  tag fix_id: 'F-23335r416351_fix'
  tag 'documentable'
  tag legacy: ['SV-111353', 'V-102409']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
