control 'SV-239146' do
  title 'The Photon operating system must use the pam_cracklib module.'
  desc 'If the operating system allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'At the command line, execute the following command:

# grep pam_cracklib /etc/pam.d/system-password

If the output does not return at least "password  requisite   pam_cracklib.so", this is a finding.

NOTE: After the fix is implemented, the check will not pass until either a reboot is performed or both files are modified, which happens automatically on reboot.'
  desc 'fix', 'Open /etc/applmgmt/appliance/system-password with a text editor.

Comment out any existing "pam_cracklib.so" line and add the following:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root

Save and close.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42357r863031_chk'
  tag severity: 'medium'
  tag gid: 'V-239146'
  tag rid: 'SV-239146r863032_rule'
  tag stig_id: 'PHTN-67-000075'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-42316r816653_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
