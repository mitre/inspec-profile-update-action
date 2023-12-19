control 'SV-93639' do
  title 'The IBM z/VM CP Privilege Class A, B, and D must be restricted to appropriate system operators.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Examine user directory definitions to determine CP Privilege class.

If CP Privilege Class A, B, or D is assigned to non-privilege users, this is a finding.'
  desc 'fix', 'Ensure that non-privilege users are not assigned CP Privilege Class A, B, or D.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78519r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78933'
  tag rid: 'SV-93639r1_rule'
  tag stig_id: 'IBMZ-VM-001010'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-85683r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
