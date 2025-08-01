control 'SV-100519' do
  title 'The SLES for vRealize must prevent the use of dictionary words for passwords.'
  desc 'If the operating system allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Verify the "passwd" command uses the "common-password" settings. 

# grep common-password /etc/pam.d/passwd

If a line "password include common-password" is not found then the "password checks in common-password" will not be applied to new passwords, and this is a finding.'
  desc 'fix', 'Configure the SLES for vRealize to prevent the use of dictionary words for passwords. 

Edit the file "/etc/pam.d/passwd". Configure "passwd" by adding a line such as: 

password include common-password

Save the changes made to the file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89561r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89869'
  tag rid: 'SV-100519r1_rule'
  tag stig_id: 'VRAU-SL-001510'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-96611r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
