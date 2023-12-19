control 'SV-239095' do
  title 'The Photon operating system must enforce password complexity by requiring that at least one numeric character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.'
  desc 'check', 'At the command line, execute the following command:

# grep pam_cracklib /etc/pam.d/system-password|grep --color=always "dcredit=.."

Expected result:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/applmgmt/appliance/system-password with a text editor.

Comment out any existing "pam_cracklib.so" line and add the following:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

Save and close.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42306r675091_chk'
  tag severity: 'medium'
  tag gid: 'V-239095'
  tag rid: 'SV-239095r816609_rule'
  tag stig_id: 'PHTN-67-000023'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-42265r816608_fix'
  tag 'documentable'
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
