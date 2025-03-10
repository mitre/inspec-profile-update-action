control 'SV-218259' do
  title 'The system must not permit root logins using remote access programs such as ssh.'
  desc 'Even though communications are encrypted, an additional layer of security may be gained by extending the policy of not logging directly on as root.  In addition, logging in with a user-specific account preserves the audit trail.'
  desc 'check', 'Determine if the SSH daemon is configured to permit root logins.

Procedure:
# grep -v "^#" /etc/ssh/sshd_config | grep -i permitrootlogin

If the PermitRootLogin entry is not found or is not set to "no", this is a finding.'
  desc 'fix', 'Edit the sshd_config file and set the PermitRootLogin option to "no".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19734r554114_chk'
  tag severity: 'medium'
  tag gid: 'V-218259'
  tag rid: 'SV-218259r603259_rule'
  tag stig_id: 'GEN001120'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag fix_id: 'F-19732r554115_fix'
  tag 'documentable'
  tag legacy: ['V-1047', 'SV-64455']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
