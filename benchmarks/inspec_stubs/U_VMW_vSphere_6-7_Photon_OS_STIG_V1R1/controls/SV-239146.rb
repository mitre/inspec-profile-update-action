control 'SV-239146' do
  title 'The Photon operating system must use the pam_cracklib module.'
  desc 'If the operating system allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'At the command line, execute the following command:

# grep pam_cracklib /etc/pam.d/system-password

If the output does not return at least "password  requisite   pam_cracklib.so", this is a finding.'
  desc 'fix', 'Open /etc/pam.d/system-password with a text editor.

Add the following, replacing any existing "pam_cracklib.so" line:

password requisite pam_cracklib.so dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1 minlen=8 minclass=4 difok=4 retry=3 maxsequence=0 enforce_for_root'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42357r675244_chk'
  tag severity: 'medium'
  tag gid: 'V-239146'
  tag rid: 'SV-239146r675246_rule'
  tag stig_id: 'PHTN-67-000075'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-42316r675245_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
