control 'SV-239103' do
  title 'The Photon operating system must enforce a minimum eight-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'At the command line, execute the following command:

# grep pam_cracklib /etc/pam.d/system-password|grep --color=always "minlen=.."

Expected result:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

If the output does not match the expected result, this is a finding.

NOTE: After the fix is implemented, the check will not pass until either a reboot is performed or both files are modified, which happens automatically on reboot.'
  desc 'fix', 'Open /etc/applmgmt/appliance/system-password with a text editor.

Comment out any existing "pam_cracklib.so" line and add the following:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

Save and close.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42314r863027_chk'
  tag severity: 'medium'
  tag gid: 'V-239103'
  tag rid: 'SV-239103r863028_rule'
  tag stig_id: 'PHTN-67-000031'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-42273r816616_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
