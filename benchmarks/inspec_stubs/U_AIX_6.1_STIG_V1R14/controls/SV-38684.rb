control 'SV-38684' do
  title 'The system must not permit root logins using remote access programs, such as ssh.'
  desc 'Even though communications are encrypted, an additional layer of security may be gained by extending the policy of not logging directly on as root. In addition, logging in with a user-specific account preserves the audit trail.'
  desc 'check', 'Determine if the SSH daemon is configured to permit root logins.

Procedure:
# find / -name sshd_config -ls
# grep -v "^#" <sshd_config path and file> | grep -i permitrootlogin

If the PermitRootLogin entry is not found or is not set to no, this is a finding.'
  desc 'fix', 'Edit the /etc/ssh/sshd_config file and set the PermitRootLogin option to no and refresh sshd. 
#kill -1 <pid of sshd>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36938r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1047'
  tag rid: 'SV-38684r1_rule'
  tag stig_id: 'GEN001120'
  tag gtitle: 'GEN001120'
  tag fix_id: 'F-32204r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
