control 'SV-29388' do
  title 'For systems utilizing a logon ID as the individual identifier, passwords must be a minimum of 14 characters in length.'
  desc 'Information systems not protected with strong password schemes including passwords of minimum length provide the opportunity for anyone to crack the password thus gaining access to the system and causing the device, information, or the local network to be compromised or a denial of service.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Account Policies -> Password Policy -> "Minimum password length" to at least "14" characters.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-6836'
  tag rid: 'SV-29388r2_rule'
  tag gtitle: 'Minimum Password Length'
  tag fix_id: 'F-53565r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Strong passwords may invite users to write down the passwords. Ensure that all users store passwords in a secured location.'
  tag third_party_tools: 'HK'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
