control 'SV-254192' do
  title 'Nutanix AOS must prevent the use of dictionary words for passwords.'
  desc 'If the operating system allows the user to select passwords based on dictionary words, then this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Confirm Nutanix AOS prevents the use of dictionary words for passwords. 

Check the /etc/pam.d/password-auth file for pam_pwquality.so

$ sudo grep pwquality.so /etc/pam.d/password-auth
password    requisite     pam_pwquality.so try_first_pass local_users_only enforce_for_root retry=3 authtok_type=
 
If the output does not contain "pam_pwquality.so" with the option of "required" or "requisite", this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to enforce the use of pam_pwquality.so by running the following command.

$ sudo salt-call state.sls security/CVM/pamCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57677r846662_chk'
  tag severity: 'medium'
  tag gid: 'V-254192'
  tag rid: 'SV-254192r846664_rule'
  tag stig_id: 'NUTX-OS-001050'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-57628r846663_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
