control 'SV-237956' do
  title 'The IBM z/VM ANY Privilege Class must not be listed for privilege commands.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Examine defined-privileged commands.

If any of the defined-privileged commands are defined with Privilege Class “ANY”, this is a finding.'
  desc 'fix', 'Review the defined-privileged commands.

Assure that CP privileged commands are not defined with a Privilege Class of “ANY”.'
  impact 0.5
  ref 'DPMS Target IBM zVM Using CA VMSecure'
  tag check_id: 'C-41166r649706_chk'
  tag severity: 'medium'
  tag gid: 'V-237956'
  tag rid: 'SV-237956r649708_rule'
  tag stig_id: 'IBMZ-VM-001210'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-41125r649707_fix'
  tag 'documentable'
  tag legacy: ['SV-93665', 'V-78959']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
