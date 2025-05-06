control 'SV-100239' do
  title 'The SLES for vRealize must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify that the SLES for vRealize enforces a minimum 15-character password length by running the following command:

# grep pam_cracklib /etc/pam.d/common-password-vmware.local

# grep pam_cracklib /etc/pam.d/common-password

If "minlen" is not set to "15" or higher, this is a finding.'
  desc 'fix', %q(If "minlen" was not set at all in /etc/pam.d/common-password-vmware.local, run the following command:

# sed -i '/pam_cracklib.so/ s/$/ minlen=15/' /etc/pam.d/common-password-vmware.local

If "minlen" was set incorrectly then run the following command to set it to "15":

# sed -i '/pam_cracklib.so/ s/minlen=../minlen=15/' /etc/pam.d/common-password-vmware.local)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89281r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89589'
  tag rid: 'SV-100239r1_rule'
  tag stig_id: 'VRAU-SL-000410'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-96331r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
