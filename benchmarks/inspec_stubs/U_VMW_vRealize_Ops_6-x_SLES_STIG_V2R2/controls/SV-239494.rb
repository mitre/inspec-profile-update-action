control 'SV-239494' do
  title 'The SLES for vRealize must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Check that SLES for vRealize enforces password complexity by requiring that at least one numeric character be used by running the following command:

# grep dcredit /etc/pam.d/common-password-vmware.local

If "dcredit" is not set to "-1" or not at all, this is a finding.

Expected Result:
password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=14 difok=4 retry=3'
  desc 'fix', %q(If dcredit was not set at all in "/etc/pam.d/common-password-vmware.local" then run the following command:

# sed -i '/pam_cracklib.so/ s/$/ dcredit=-1/' /etc/pam.d/common-password-vmware.local

If "dcredit" was set incorrectly, run the following command to set it to "-1":

# sed -i '/pam_cracklib.so/ s/dcredit=../dcredit=-1/' /etc/pam.d/common-password-vmware.local)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42727r661931_chk'
  tag severity: 'medium'
  tag gid: 'V-239494'
  tag rid: 'SV-239494r661933_rule'
  tag stig_id: 'VROM-SL-000355'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-42686r661932_fix'
  tag 'documentable'
  tag legacy: ['SV-99109', 'V-88459']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
