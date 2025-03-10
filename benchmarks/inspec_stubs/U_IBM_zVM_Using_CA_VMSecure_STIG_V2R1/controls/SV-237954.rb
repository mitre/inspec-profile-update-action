control 'SV-237954' do
  title 'The IBM z/VM Privilege Classes C and E must be restricted to appropriate system administrators.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Examine user directory definitions to determine privilege class.

If the CP privilege Class C is assigned to system programmers only, this is not a finding.

If the CP privilege Class E is assigned to system analyst only, this is not a finding.'
  desc 'fix', 'Configure the CP Privilege Class.

Assign CP Privilege Classes, C and E, to system programmers and/or system analysts only.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41164r649700_chk'
  tag severity: 'medium'
  tag gid: 'V-237954'
  tag rid: 'SV-237954r649702_rule'
  tag stig_id: 'IBMZ-VM-001190'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-41123r649701_fix'
  tag 'documentable'
  tag legacy: ['SV-93661', 'V-78955']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
