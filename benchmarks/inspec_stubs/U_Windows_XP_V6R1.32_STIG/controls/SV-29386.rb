control 'SV-29386' do
  title 'For systems utilizing a logon ID as the individual identifier, passwords are not at a minimum of 14-characters.'
  desc 'Information systems not protected with strong password schemes including passwords of minimum length provide the opportunity for anyone to crack the password thus gaining access to the system and causing the device, information, or the local network to be compromised or a denial of service.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Account Policies -> Password Policy.

If the value for the “Minimum password length,” is less than 14 characters, then this is a finding.'
  desc 'fix', 'Configure all information systems to require passwords of the minimum length specified in the check.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-3225r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6836'
  tag rid: 'SV-29386r1_rule'
  tag gtitle: 'Minimum Password Length'
  tag fix_id: 'F-6523r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Strong passwords may invite users to write down the passwords. Ensure that all users store passwords in a secured location.'
  tag third_party_tools: 'HK'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'IAIA-1, IAIA-2'
end
