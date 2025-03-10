control 'SV-93663' do
  title 'The IBM z/VM Privilege Class F must be restricted to service representatives and system administrators only.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.

Privilege Class F can obtain, and examine in detail, data about input and output devices connected to the z/VM system. This privilege class is reserved for IBM use only.'
  desc 'check', 'Examine user directory definitions to determine Privilege Class.

If CP Privilege Class F is assigned to anyone other than a service representative or system administrator, this is a finding.'
  desc 'fix', 'Configure CP Privilege Class F to service representatives and system administrators only.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78543r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78957'
  tag rid: 'SV-93663r1_rule'
  tag stig_id: 'IBMZ-VM-001200'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-85707r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
