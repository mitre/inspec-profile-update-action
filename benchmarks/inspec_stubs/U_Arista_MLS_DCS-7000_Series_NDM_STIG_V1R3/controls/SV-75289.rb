control 'SV-75289' do
  title 'The Arista Multilayer Switch account of last resort must have a password with a length of 15 characters.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that needs to be tested before the password is compromised.

Typically, the account of last resort is a built-in account with full privileges to the network device. This account should only be used when the authentication mechanism is unreachable and configuration or maintenance actions must be taken.'
  desc 'check', 'Review the Arista Multilayer Switch configuration for the account of last resort with full access to the network device.

If the account of last resort does not require a password length of at least 15 characters, this is a finding.

To verify the setting is correct, run the "show running-config" command on the switch. Under the section "management security", the configuration statement "password minimum length 15" must be present, with a value set to 15 or higher.'
  desc 'fix', 'Configure the Arista Multilayer Switch account of last resort with a password with a length of at least 15 characters.

To configure the password minimum length, enter the following commands:

configure
management security
password minimum length 15'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61779r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60833'
  tag rid: 'SV-75289r1_rule'
  tag stig_id: 'AMLS-NM-000110'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-66543r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
