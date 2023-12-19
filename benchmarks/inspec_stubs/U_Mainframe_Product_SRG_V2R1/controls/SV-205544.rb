control 'SV-205544' do
  title 'The Mainframe Product must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.'
  desc 'check', 'Examine installation and configuration settings.

Determine the Mainframe Product privileged functions.

If the Mainframe Product uses an external security manager (ESM) for access authorizations, verify the ESM prevents access to privileged functions to appropriate privileged users. If it does not, this is a finding.

If the Mainframe Product does not use an ESM to verify installation and configuration settings to prevent access to privileged functions to appropriate privileged users, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to prevent non-privileged users from executing privileged functions. This can be accomplished using the ESM.

Configure the ESM to restrict update and higher access to privileged functions to privileged users.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5810r299865_chk'
  tag severity: 'medium'
  tag gid: 'V-205544'
  tag rid: 'SV-205544r851312_rule'
  tag stig_id: 'SRG-APP-000340-MFP-000088'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-5810r299866_fix'
  tag 'documentable'
  tag legacy: ['SV-82659', 'V-68169']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
