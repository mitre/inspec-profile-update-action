control 'SV-240496' do
  title 'The SLES for vRealize must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity or strength is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'Verify the SLES for vRealize enforces password complexity by requiring that at least one special character be used by using the following command:

Check the password "ocredit" option:

# grep pam_cracklib.so /etc/pam.d/common-password

Confirm the "ocredit" option is set to "-1" as in the example:

password requisite pam_cracklib.so ocredit=-1

There may be other options on the line. 

If no such line is found, or the "ocredit" is not "-1", this is a finding.'
  desc 'fix', %q(Configure the SLES for vRealize to enforce password complexity by requiring that at least one special character be used:

If "ocredit" was not set at all in /etc/pam.d/common-password-vmware.local then run the following command:

# sed -i '/pam_cracklib.so/ s/$/ ocredit=-1/' /etc/pam.d/common-password-vmware.local

If "ocredit" was set incorrectly then run the following command:

# sed -i '/pam_cracklib.so/ s/ocredit=../ocredit=-1/' /etc/pam.d/common-password-vmware.local)
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43729r671227_chk'
  tag severity: 'medium'
  tag gid: 'V-240496'
  tag rid: 'SV-240496r671229_rule'
  tag stig_id: 'VRAU-SL-000925'
  tag gtitle: 'SRG-OS-000266-GPOS-00101'
  tag fix_id: 'F-43688r671228_fix'
  tag 'documentable'
  tag legacy: ['SV-100419', 'V-89769']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
