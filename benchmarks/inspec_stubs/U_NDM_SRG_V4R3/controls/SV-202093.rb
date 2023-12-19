control 'SV-202093' do
  title 'The network device must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. 

Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals that do not possess appropriate authorizations.'
  desc 'check', 'Determine if the network device prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.  This requirement may be verified by demonstration, configuration review, or validated test results. If the network device does not prevent non-privileged users from executing privileged functions, this is a finding.'
  desc 'fix', 'Configure the network device to prevent non-privileged users from executing privileged functions.'
  impact 0.7
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2219r381920_chk'
  tag severity: 'high'
  tag gid: 'V-202093'
  tag rid: 'SV-202093r879717_rule'
  tag stig_id: 'SRG-APP-000340-NDM-000288'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-2220r381921_fix'
  tag 'documentable'
  tag legacy: ['SV-69467', 'V-55221']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
