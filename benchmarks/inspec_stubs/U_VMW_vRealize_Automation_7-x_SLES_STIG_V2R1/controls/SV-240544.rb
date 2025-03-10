control 'SV-240544' do
  title 'The SLES for vRealize must prevent the use of dictionary words for passwords.'
  desc 'If the operating system allows the user to select passwords based on dictionary words,  this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Check "/etc/pam.d/common-password" for "pam_cracklib" configuration:

# grep pam_cracklib /etc/pam.d/common-password*

If "pam_cracklib" is not present, this is a finding.

Ensure the "passwd" command uses the "common-password" settings.

# grep common-password /etc/pam.d/passwd

If a line "password include common-password" is not found then the "password checks in common-password" will not be applied to new passwords, this is a finding.'
  desc 'fix', 'Edit "/etc/pam.d/common-password" and configure "pam_cracklib" by adding a line such as "password requisite pam_cracklib.so"'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43777r671371_chk'
  tag severity: 'medium'
  tag gid: 'V-240544'
  tag rid: 'SV-240544r671373_rule'
  tag stig_id: 'VRAU-SL-001500'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-43736r671372_fix'
  tag 'documentable'
  tag legacy: ['SV-100515', 'V-89865']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
