control 'SV-37318' do
  title 'The system must prevent the use of dictionary words for passwords.'
  desc 'An easily guessable password provides an open door to any external or internal malicious intruder.  Many computer compromises occur as the result of account name and password guessing.  This is generally done by someone with an automated script that uses repeated logon attempts until the correct account and password pair is guessed.  Utilities, such as cracklib, can be used to validate passwords are not dictionary words and meet other criteria during password changes.'
  desc 'check', 'Check /etc/pam.d/system-auth for pam_cracklib configuration.

Procedure:
# grep pam_cracklib /etc/pam.d/system-auth*
If pam_cracklib is not present. This is a finding.

If pam_cracklib is present only in /etc/pam.d/system-auth-ac:
ensure that /etc/pam.d/system-auth includes /etc/pam.d/system-auth-ac.
#grep system-auth-ac /etc/pam.d/system-auth

This should return:
auth include system-auth-ac
account include system-auth-ac
password include system-auth-ac
session include system-auth-ac

/etc/pam.d/system-auth-ac should only be included by /etc/pam.d/system-auth. All other pam files should include /etc/pam.d/system-auth. 

If pam_cracklib is not defined in /etc/pam.d/system-auth either directly or through inclusion of system-auth-ac, this is a finding.

Ensure the passwd command uses the system-auth settings.
# grep system-auth /etc/pam.d/passwd

If a line "password include system-auth" is not found then the password checks in system-auth will not be applied to new passwords, this is a finding.'
  desc 'fix', 'If /etc/pam.d/system-auth references /etc/pam.d/system-auth-ac refer to the man page for system-auth-ac for a description of how to add options not configurable with authconfig. Edit /etc/pam.d/system-auth and configure pam_cracklib by adding a line such as "password required pam_cracklib.so"'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36011r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22307'
  tag rid: 'SV-37318r1_rule'
  tag stig_id: 'GEN000790'
  tag gtitle: 'GEN000790'
  tag fix_id: 'F-31262r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000189']
  tag nist: ['IA-5 (4)']
end
