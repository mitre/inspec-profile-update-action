control 'SV-219184' do
  title 'The Ubuntu operating system must prevent the use of dictionary words for passwords.'
  desc 'If the Ubuntu operating system allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Verify that the Ubuntu operating system uses the cracklib library to prevent the use of dictionary words with the following command:

# grep dictcheck /etc/security/pwquality.conf

dictcheck=1

If the "dictcheck" parameter is not set to "1", or is commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to prevent the use of dictionary words for passwords.

Add or update the following line in the "/etc/security/pwquality.conf" file to include the "dictcheck=1" parameter:

dictcheck=1'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20909r304880_chk'
  tag severity: 'medium'
  tag gid: 'V-219184'
  tag rid: 'SV-219184r610963_rule'
  tag stig_id: 'UBTU-18-010113'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-20908r304881_fix'
  tag 'documentable'
  tag legacy: ['V-100595', 'SV-109699']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
