control 'SV-256506' do
  title 'The Photon operating system must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the result is a password that is not changed per policy requirements.'
  desc 'check', 'At the command line, run the following command:

# grep pam_pwhistory /etc/pam.d/system-password|grep --color=always "remember=."

Expected result:

password requisite pam_pwhistory.so enforce_for_root use_authtok remember=5 retry=3

If the output does not include the "remember=5" setting as shown in the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/pam.d/system-password

Add the following line after the "password requisite pam_cracklib.so" statement:

password requisite pam_pwhistory.so enforce_for_root use_authtok remember=5 retry=3

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA Photon OS'
  tag check_id: 'C-60181r887190_chk'
  tag severity: 'medium'
  tag gid: 'V-256506'
  tag rid: 'SV-256506r887192_rule'
  tag stig_id: 'PHTN-30-000029'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-60124r887191_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
