control 'SV-99125' do
  title 'The SLES for vRealize must prohibit password reuse for a minimum of five generations. Ensure the old passwords are being stored.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify that the old password file, "opasswd", exists, by running the following command:

# ls /etc/security/opasswd

If "/etc/security/opasswd" file does not exist, this is a finding.'
  desc 'fix', 'Create the password history file. 

# touch /etc/security/opasswd
# chown root:root /etc/security/opasswd
# chmod 0600 /etc/security/opasswd'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88167r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88475'
  tag rid: 'SV-99125r1_rule'
  tag stig_id: 'VROM-SL-000400'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-95217r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
