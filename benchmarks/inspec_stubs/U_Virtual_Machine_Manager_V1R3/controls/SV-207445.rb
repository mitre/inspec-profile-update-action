control 'SV-207445' do
  title 'The VMM must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Verify the VMM prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7702r365745_chk'
  tag severity: 'medium'
  tag gid: 'V-207445'
  tag rid: 'SV-207445r854618_rule'
  tag stig_id: 'SRG-OS-000324-VMM-001150'
  tag gtitle: 'SRG-OS-000324'
  tag fix_id: 'F-7702r365746_fix'
  tag 'documentable'
  tag legacy: ['V-57091', 'SV-71351']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
