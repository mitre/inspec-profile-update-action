control 'SV-239101' do
  title 'The Photon operating system must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'At the command line, execute the following command:

# grep pam_pwhistory /etc/pam.d/system-password|grep --color=always "remember=."

Expected result:

password required pam_pwhistory.so enforce_for_root use_authtok remember=5 retry=3

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Open /etc/pam.d/system-password with a text editor.

Add the following line after the last auth statement:

password required pam_pwhistory.so enforce_for_root use_authtok remember=5 retry=3'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42312r675109_chk'
  tag severity: 'medium'
  tag gid: 'V-239101'
  tag rid: 'SV-239101r675111_rule'
  tag stig_id: 'PHTN-67-000029'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-42271r675110_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
