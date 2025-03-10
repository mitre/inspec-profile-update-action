control 'SV-209029' do
  title 'The system must require passwords to contain no more than three consecutive repeating characters.'
  desc 'Passwords with excessive repeating characters may be more vulnerable to password-guessing attacks.'
  desc 'check', 'To check the maximum value for consecutive repeating characters, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

Look for the value of the "maxrepeat" parameter. The DoD requirement is “3”.

If "maxrepeat" is not found, is set to zero, or is set to a value greater than “3”, this is a finding.'
  desc 'fix', %q(The pam_cracklib module's ”maxrepeat” parameter controls requirements for consecutive repeating characters. When set to a positive number, it will reject passwords that contain more than the number of consecutive characters.

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "maxrepeat=3" after pam_cracklib.so to prevent a run of (3 + 1) or more identical characters.
password required pam_cracklib.so maxrepeat=3)
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9282r357872_chk'
  tag severity: 'low'
  tag gid: 'V-209029'
  tag rid: 'SV-209029r793750_rule'
  tag stig_id: 'OL6-00-000299'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9282r357873_fix'
  tag 'documentable'
  tag legacy: ['SV-65201', 'V-50995']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
