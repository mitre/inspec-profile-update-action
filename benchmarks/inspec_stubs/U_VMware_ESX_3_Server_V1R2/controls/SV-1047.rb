control 'SV-1047' do
  title 'The system must not permit root logins using remote access programs, such as SSH.'
  desc 'Even though communications are encrypted, an additional layer of security may be gained by extending the policy of not logging directly on as root. In addition, logging in with a user-specific account preserves the audit trail.'
  desc 'check', 'Determine if the SSH daemon is configured to permit root logins.

Procedure:
# find / -name sshd_config -print
# grep -v "^#" <sshd_config path> | grep -i permitrootlogin

If the PermitRootLogin entry is not found or is not set to no, this is a finding.'
  desc 'fix', 'Edit the configuration file and set the PermitRootLogin option to no.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-892r2_chk'
  tag severity: 'medium'
  tag gid: 'V-1047'
  tag rid: 'SV-1047r2_rule'
  tag stig_id: 'GEN001120'
  tag gtitle: 'GEN001120'
  tag fix_id: 'F-24426r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECPA-1'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
