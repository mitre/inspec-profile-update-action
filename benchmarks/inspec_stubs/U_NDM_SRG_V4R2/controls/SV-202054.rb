control 'SV-202054' do
  title 'The network device must be configured to authenticate each administrator prior to authorizing privileges based on assignment of group or role.'
  desc 'To assure individual accountability and prevent unauthorized access, administrators must be individually identified and authenticated. 

Individual accountability mandates that each administrator is uniquely identified. A group authenticator is a shared account or some other form of authentication that allows multiple unique individuals to access the network device using a single account. 

If a device allows or provides for group authenticators, it must first individually authenticate administrators prior to implementing group authenticator functionality. 

Some devices may not have the need to provide a group authenticator; this is considered a matter of device design. In those instances where the device design includes the use of a group authenticator, this requirement will apply.  This requirement applies to accounts created and managed on or by the network device.'
  desc 'check', 'Determine if the network device ensures that administrators are authenticated with an individual authenticator prior to using a group authenticator.  This requirement may be verified by demonstration, configuration review, or validated test results. If the network device does not authenticate administrators with an individual authenticator prior to using a group authenticator, this is a finding.'
  desc 'fix', 'Configure the network device to ensure administrators are authenticated with an individual authenticator prior to using a group authenticator.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2180r381758_chk'
  tag severity: 'medium'
  tag gid: 'V-202054'
  tag rid: 'SV-202054r879594_rule'
  tag stig_id: 'SRG-APP-000153-NDM-000249'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-2181r381759_fix'
  tag 'documentable'
  tag legacy: ['SV-69355', 'V-55109']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
