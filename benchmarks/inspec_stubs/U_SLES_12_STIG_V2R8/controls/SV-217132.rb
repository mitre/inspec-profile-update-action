control 'SV-217132' do
  title 'The SUSE operating system must employ a password history file.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify the password history file exists on the SUSE operating system.

Check that the password history file exists with the following command:

# ls -al /etc/security/opasswd

-rw------- 1 root root 7 Dec 13 17:21 /etc/security/opasswd

If "/etc/security/opasswd" does not exist, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to create the password history file with the following commands:

# sudo touch /etc/security/opasswd
# sudo chown root:root /etc/security/opasswd
# sudo chmod 0600 /etc/security/opasswd'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18360r369552_chk'
  tag severity: 'medium'
  tag gid: 'V-217132'
  tag rid: 'SV-217132r603262_rule'
  tag stig_id: 'SLES-12-010300'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-18358r369553_fix'
  tag 'documentable'
  tag legacy: ['SV-91815', 'V-77119']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
