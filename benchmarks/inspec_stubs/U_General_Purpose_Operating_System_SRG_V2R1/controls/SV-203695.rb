control 'SV-203695' do
  title 'The operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Verify that the operating system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3820r375032_chk'
  tag severity: 'medium'
  tag gid: 'V-203695'
  tag rid: 'SV-203695r379591_rule'
  tag stig_id: 'SRG-OS-000324-GPOS-00125'
  tag gtitle: 'SRG-OS-000324'
  tag fix_id: 'F-3820r375033_fix'
  tag 'documentable'
  tag legacy: ['V-57231', 'SV-71491']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
