control 'SV-99409' do
  title 'The SLES for vRealize must prevent the use of dictionary words for passwords.'
  desc 'If SLES for vRealize system allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Check "/etc/pam.d/common-password" for "pam_cracklib" configuration:

# grep pam_cracklib /etc/pam.d/common-password*

If "pam_cracklib" is not present, this is a finding.

Ensure the passwd command uses the common-password settings.

# grep common-password /etc/pam.d/passwd

If a line "password include common-password" is not found then the password checks in common-password will not be applied to new passwords, this is a finding.'
  desc 'fix', 'Edit "/etc/pam.d/common-password" and configure "pam_cracklib" by adding a line such as "password requisite pam_cracklib.so".'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88451r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88759'
  tag rid: 'SV-99409r1_rule'
  tag stig_id: 'VROM-SL-001475'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-95501r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
