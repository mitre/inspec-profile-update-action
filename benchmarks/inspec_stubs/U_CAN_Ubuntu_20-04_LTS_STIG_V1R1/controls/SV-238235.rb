control 'SV-238235' do
  title 'The Ubuntu operating system must automatically lock an account until the locked account is released by an administrator when three unsuccessful logon attempts have been made.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.

'
  desc 'check', 'Verify the Ubuntu operating system locks an account after three unsuccessful login attempts with following command: 
 
$ grep  pam_tally2 /etc/pam.d/common-auth  
 
auth required pam_tally2.so onerr=fail deny=3 
 
If no line is returned or the line is commented out, this is a finding. 
 
If the line is missing "onerr=fail", this is a finding. 
 
If the line has "deny" set to a value more than "3", this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to lock an account after three unsuccessful login attempts.  
 
Edit the "/etc/pam.d/common-auth" file. The "pam_tally2.so" entry must be placed at the top of the "auth" stack. 
 
Add the following line before the first "auth" entry in the file: 
 
auth required pam_tally2.so onerr=fail deny=3'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41445r653878_chk'
  tag severity: 'low'
  tag gid: 'V-238235'
  tag rid: 'SV-238235r653880_rule'
  tag stig_id: 'UBTU-20-010072'
  tag gtitle: 'SRG-OS-000329-GPOS-00128'
  tag fix_id: 'F-41404r653879_fix'
  tag satisfies: ['SRG-OS-000329-GPOS-00128', 'SRG-OS-000021-GPOS-00005']
  tag 'documentable'
  tag cci: ['CCI-000044', 'CCI-002238']
  tag nist: ['AC-7 a', 'AC-7 b']
end
