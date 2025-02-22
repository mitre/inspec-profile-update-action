control 'SV-100235' do
  title 'The SLES for vRealize must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify that the SLES for vRealize prohibits the reuse of a password for a minimum of five generations by running the following commands:

# grep pam_pwhistory.so /etc/pam.d/common-password-vmware.local 

If the "remember" option in /etc/pam.d/common-password-vmware.local is not "5" or greater, this is a finding.'
  desc 'fix', %q(Configure pam to use password history. 

If "remember" was not set at all in /etc/pam.d/common-password-vmware.local, run the following command:

# sed -i '/pam_cracklib.so/ s/$/ remember=5/' /etc/pam.d/common-password-vmware.local

If "remember" was set incorrectly, run the following command to set it to "5":

# sed -i '/pam_cracklib.so/ s/remember=./remember=5/' /etc/pam.d/common-password-vmware.local)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89277r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89585'
  tag rid: 'SV-100235r1_rule'
  tag stig_id: 'VRAU-SL-000400'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-96327r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
