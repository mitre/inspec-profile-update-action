control 'SV-254220' do
  title 'Nutanix AOS must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Confirm Nutanix AOS is configured to prohibit password reuse for a minimum of five generations.

$ sudo grep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth
password requisite pam_pwhistory.so use_authtok remember=5 retry=3

If the line containing the "pam_pwhistory.so" line does not have the "remember" module argument set, is commented out, or the value of the "remember" module argument is set to less than "5", this is a finding.'
  desc 'fix', 'Configure the password maximum age by running the following command:

$ sudo salt-call state.sls security/CVM/pamCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57705r846746_chk'
  tag severity: 'medium'
  tag gid: 'V-254220'
  tag rid: 'SV-254220r846748_rule'
  tag stig_id: 'NUTX-OS-001360'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-57656r846747_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
