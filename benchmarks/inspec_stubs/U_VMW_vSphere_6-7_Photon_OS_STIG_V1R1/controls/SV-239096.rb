control 'SV-239096' do
  title 'The Photon operating system must require that new passwords are at least four characters different from the old password.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.'
  desc 'check', 'At the command line, execute the following command:

# grep pam_cracklib /etc/pam.d/system-password|grep --color=always "difok=."

Expected result:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/pam.d/system-password with a text editor.

Add the following, replacing any existing "pam_cracklib.so" line:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42307r675094_chk'
  tag severity: 'medium'
  tag gid: 'V-239096'
  tag rid: 'SV-239096r675096_rule'
  tag stig_id: 'PHTN-67-000024'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-42266r675095_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
