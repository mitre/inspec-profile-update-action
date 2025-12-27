control 'SV-226483' do
  title 'The system must not permit root logins using remote access programs such as SSH.'
  desc 'Even though communications are encrypted, an additional layer of security may be gained by extending the policy of not logging directly on as root. In addition, logging in with a user-specific account preserves the audit trail.'
  desc 'check', 'Determine if the SSH daemon is configured to permit root logins.

Procedure:
# grep -v "^#" /etc/ssh/sshd_config | grep -i permitrootlogin

If the PermitRootLogin entry is not found or is not set to "no", this is a finding.'
  desc 'fix', 'Edit the configuration file and set the PermitRootLogin option to no.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28644r482834_chk'
  tag severity: 'medium'
  tag gid: 'V-226483'
  tag rid: 'SV-226483r603265_rule'
  tag stig_id: 'GEN001120'
  tag gtitle: 'SRG-OS-000109'
  tag fix_id: 'F-28632r482835_fix'
  tag 'documentable'
  tag legacy: ['V-1047', 'SV-39811']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
