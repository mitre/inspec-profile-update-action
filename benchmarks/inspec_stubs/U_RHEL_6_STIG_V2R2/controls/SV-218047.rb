control 'SV-218047' do
  title 'The system must require passwords to contain no more than three consecutive repeating characters.'
  desc 'Passwords with excessive repeating characters may be more vulnerable to password-guessing attacks.'
  desc 'check', 'To check the maximum value for consecutive repeating characters, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

Look for the value of the "maxrepeat" parameter.

If "maxrepeat" is not found, is set to zero, or is set to a value greater than "3", this is a finding.'
  desc 'fix', %q(The pam_cracklib module's "maxrepeat" parameter controls requirements for consecutive repeating characters. When set to a positive number, it will reject passwords which contain more than that number of consecutive characters.

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "maxrepeat=3" after pam_cracklib.so to prevent a run of (3 + 1) or more identical characters.

password required pam_cracklib.so maxrepeat=3)
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19528r377156_chk'
  tag severity: 'low'
  tag gid: 'V-218047'
  tag rid: 'SV-218047r603264_rule'
  tag stig_id: 'RHEL-06-000299'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19526r377157_fix'
  tag 'documentable'
  tag legacy: ['SV-50494', 'V-38693']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
