control 'SV-234893' do
  title 'The SUSE operating system must employ a password history file.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify the password history file exists on the SUSE operating system.

Check that the password history file exists with the following command:

> ls -al /etc/security/opasswd

-rw------- 1 root root 7 Dec 13 17:21 /etc/security/opasswd

If "/etc/security/opasswd" does not exist, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to create the password history file with the following commands:

> sudo touch /etc/security/opasswd
> sudo chown root:root /etc/security/opasswd
> sudo chmod 0600 /etc/security/opasswd'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38081r618948_chk'
  tag severity: 'medium'
  tag gid: 'V-234893'
  tag rid: 'SV-234893r622137_rule'
  tag stig_id: 'SLES-15-020240'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-38044r618949_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
