control 'SV-240405' do
  title 'The SLES for vRealize must prohibit password reuse for a minimum of five generations - old passwords are being stored.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify that the old password file "opasswd" exists, by running the following command:

# ls /etc/security/opasswd

If "/etc/security/opasswd" does not exist, this is a finding.'
  desc 'fix', 'Create the password history file.

# touch /etc/security/opasswd
# chown root:root /etc/security/opasswd
# chmod 0600 /etc/security/opasswd'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43638r670954_chk'
  tag severity: 'medium'
  tag gid: 'V-240405'
  tag rid: 'SV-240405r670956_rule'
  tag stig_id: 'VRAU-SL-000405'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-43597r670955_fix'
  tag 'documentable'
  tag legacy: ['SV-100237', 'V-89587']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
