control 'SV-75271' do
  title 'The Arista Multilayer Switch must have a local infrequently used account to be used as an account of last resort with full access to the network device.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that needs to be tested before the password is compromised.

Typically, the account of last resort is a built-in account with full privileges to the network device. This account should only be used when the authentication mechanism is unreachable and configuration or maintenance actions must be taken.'
  desc 'check', 'Review the Arista Multilayer Switch configuration for a local infrequently used account to be used as an account of last resort with full access to the network device. The default account on the Arista MLS is called admin.

If the account of last resort does not exist, this is a finding.

To assign a password to this account, enter the following:

username admin secret [password] role [role]'
  desc 'fix', 'Configure the Arista Multilayer Switch with a local infrequently used account to be used as an account of last resort with full access to the network device.'
  impact 0.7
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61737r1_chk'
  tag severity: 'high'
  tag gid: 'V-60815'
  tag rid: 'SV-75271r1_rule'
  tag stig_id: 'AMLS-NM-000100'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-66501r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
