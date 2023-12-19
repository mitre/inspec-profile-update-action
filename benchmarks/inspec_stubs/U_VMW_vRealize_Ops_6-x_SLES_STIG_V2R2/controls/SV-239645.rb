control 'SV-239645' do
  title 'The SLES for vRealize must prevent the use of dictionary words for passwords.'
  desc 'If SLES for vRealize allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Verify the module "pam_cracklib.so" is present. 

Procedure: 

# ls /lib/security/
 
Confirm that "pam_cracklib.so" is present in the directory listing. 

If "pam_cracklib.so"  is not present, this is a finding.

Verify the file "/etc/pam.d/common-password" is configured.

Procedure: 

# grep pam_cracklib /etc/pam.d/common-password*

If a line containing "password required pam_cracklib.so" is not present, this is a finding.'
  desc 'fix', 'Configure SLES for vRealize to prevent the use of dictionary words for passwords.

Edit the file "/etc/pam.d/common-password". Configure "common-password" by adding a line such as: 

password  required pam_cracklib.so

Save the changes made to the file "/etc/pam.d/common-password".'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42878r662384_chk'
  tag severity: 'medium'
  tag gid: 'V-239645'
  tag rid: 'SV-239645r662386_rule'
  tag stig_id: 'VROM-SL-001480'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-42837r662385_fix'
  tag 'documentable'
  tag legacy: ['SV-99411', 'V-88761']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
