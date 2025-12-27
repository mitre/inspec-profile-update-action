control 'SV-243135' do
  title 'The network device must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Review the network device configuration to determine if the network device is configured with a password of at least 15 characters.

If the network device password is not at least 15 characters in length, this is a finding.'
  desc 'fix', 'Configure the network device so it will require a password to gain administrative access to the device. Configure the password length to at least 15 characters.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-IG Mgmt'
  tag check_id: 'C-46410r719858_chk'
  tag severity: 'medium'
  tag gid: 'V-243135'
  tag rid: 'SV-243135r719860_rule'
  tag stig_id: 'WLAN-ND-000200'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-46367r719859_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
