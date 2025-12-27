control 'SV-239646' do
  title 'The SLES for vRealize must prevent the use of dictionary words for passwords.'
  desc 'If SLES for vRealize allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Verify the "passwd" command uses the "common-password" settings.

Procedure:

# grep common-password /etc/pam.d/passwd

If line "password include common-password" is not found then the password checks in common-password will not be applied to new passwords, and this is a finding.'
  desc 'fix', 'Configure SLES for vRealize to prevent the use of dictionary words for passwords. Procedure:

Edit the file "/etc/pam.d/passwd". Configure "passwd" by adding a line such as: 

password include common-password

Save the changes made to the file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42879r662387_chk'
  tag severity: 'medium'
  tag gid: 'V-239646'
  tag rid: 'SV-239646r662389_rule'
  tag stig_id: 'VROM-SL-001485'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-42838r662388_fix'
  tag 'documentable'
  tag legacy: ['SV-99413', 'V-88763']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
