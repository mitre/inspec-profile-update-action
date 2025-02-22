control 'SV-237914' do
  title 'IBM zVM CA VM:Secure product PASSWORD user exit must be in use.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.


'
  desc 'check', 'If there is no CA VM:Secure PASSWORD user exit in use, this is a finding.

Review the CA VM:Secure Password user exit.

If there is no code that enforces a minimum 8-character password, this is a finding.

If there is no code that prohibits the use of all numbers in the new password, this is a finding.

If there is no code that prohibits the use of user name in the new password, this is a finding.

If there is no code that prohibits the use of userID in the new password, this is a finding.

If there is no code that prohibits the use of consecutive repeated characters, this is a finding.

If there is no code requiring that at least one special character be used in the new password, this is a finding.

If there is no code that enforces 24 hours/1 day as the minimum password lifetime, this is a finding.

If there is no code that enforces a minimum that at least one lowercase character is used in the new password, this is a finding.

If there is no code that enforces a minimum that at least one numeric character is used in the new password, this is a finding.

If there is no code that enforces a minimum that at least one uppercase character is used in the new password, this is a finding.

If there is no code that enforces change of at least 50% of the total number of characters when passwords are changed, this is a finding.'
  desc 'fix', 'Configure a CA VM:Secure PASSWORD user exit that enforces a minimum 8-character password length.

Ensure that the following macros are updated with proper PASSWORD user exit:

FORCEPWC
VMXCHGPW
MAINT
USE00080'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41124r649580_chk'
  tag severity: 'medium'
  tag gid: 'V-237914'
  tag rid: 'SV-237914r649582_rule'
  tag stig_id: 'IBMZ-VM-000520'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-41083r649581_fix'
  tag satisfies: ['SRG-OS-000078-GPOS-00046', 'SRG-OS-000480-GPOS-00227', 'SRG-OS-000480-GPOS-00227', 'SRG-OS-000266-GPOS-00101', 'SRG-OS-000075-GPOS-00043', 'SRG-OS-000070-GPOS-00038', 'SRG-OS-000071-GPOS-00039', 'SRG-OS-000069-GPOS-00037', 'SRG-OS-000072-GPOS-00040']
  tag 'documentable'
  tag legacy: ['SV-93581', 'V-78875']
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000195', 'CCI-000198', 'CCI-000205', 'CCI-000366', 'CCI-001619']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (a)', 'IA-5 (1) (b)', 'IA-5 (1) (d)', 'IA-5 (1) (a)', 'CM-6 b', 'IA-5 (1) (a)']
end
