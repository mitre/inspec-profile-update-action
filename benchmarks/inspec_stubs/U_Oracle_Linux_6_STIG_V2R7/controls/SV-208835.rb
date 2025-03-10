control 'SV-208835' do
  title 'The system must require at least eight characters be changed between the old and new passwords during a password change.'
  desc 'Requiring a minimum number of different characters during password changes ensures that newly changed passwords should not resemble previously compromised ones. Note: Passwords which are changed on compromised systems will still be compromised.'
  desc 'check', 'To check how many characters must differ during a password change, run the following command:

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

The "difok" parameter will indicate how many characters must differ. The DoD requires eight characters differ during a password change. This would appear as "difok=8".

If the “difok” parameter is not found or not set to the required value, this is a finding.'
  desc 'fix', %q(The pam_cracklib module's "difok" parameter controls requirements for usage of different characters during a password change.

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "difok=[NUM]" after pam_cracklib.so to require differing characters when changing passwords, substituting [NUM] appropriately. The DoD requirement is “8”.)
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9088r357485_chk'
  tag severity: 'low'
  tag gid: 'V-208835'
  tag rid: 'SV-208835r793620_rule'
  tag stig_id: 'OL6-00-000060'
  tag gtitle: 'SRG-OS-000072'
  tag fix_id: 'F-9088r357486_fix'
  tag 'documentable'
  tag legacy: ['SV-65125', 'V-50919']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
