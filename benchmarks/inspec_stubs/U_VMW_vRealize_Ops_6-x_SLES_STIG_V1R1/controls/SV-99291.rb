control 'SV-99291' do
  title 'The SLES for vRealize must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'Verify SLES for vRealize enforces password complexity by requiring that at least one special character be used by using the following command:

Check the password "ocredit" option:

# grep pam_cracklib.so /etc/pam.d/common-password

Confirm the "ocredit" option is set to "-1" as in the example: 

password requisite pam_cracklib.so ocredit=-1

There may be other options on the line. 

If no such line is found, or the "ocredit" is not "-1", this is a finding.'
  desc 'fix', %q(Configure SLES for vRealize to enforce password complexity by requiring that at least one special character be used by running the following command:

If "ocredit" was not set at all in "/etc/pam.d/common-password-vmware.local" file then run the following command:

# sed -i '/pam_cracklib.so/ s/$/ ocredit=-1/' /etc/pam.d/common-password-vmware.local

If "ocredit" was set incorrectly, run the following command:

# sed -i '/pam_cracklib.so/ s/ocredit=../ocredit=-1/' /etc/pam.d/common-password-vmware.local)
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88333r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88641'
  tag rid: 'SV-99291r1_rule'
  tag stig_id: 'VROM-SL-000900'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-95383r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
