control 'SV-239501' do
  title 'The SLES for vRealize must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify that SLES for vRealize prohibits the reuse of a password for a minimum of five generations, by running the following commands:

# grep pam_pwhistory.so /etc/pam.d/common-password-vmware.local 

If the "remember" option in "/etc/pam.d/common-password-vmware.local" file is not "5" or greater, this is a finding.'
  desc 'fix', %q(Configure pam to use password history. 

If the "remember" option was not set at all in "/etc/pam.d/common-password-vmware.local" file then run the following command:

# sed -i '/pam_cracklib.so/ s/$/ remember=5/' /etc/pam.d/common-password-vmware.local

If "remember" option was set incorrectly, run the following command to set it to "5":

# sed -i '/pam_cracklib.so/ s/remember=./remember=5/' /etc/pam.d/common-password-vmware.local)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42734r661952_chk'
  tag severity: 'medium'
  tag gid: 'V-239501'
  tag rid: 'SV-239501r661954_rule'
  tag stig_id: 'VROM-SL-000395'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-42693r661953_fix'
  tag 'documentable'
  tag legacy: ['SV-99123', 'V-88473']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
