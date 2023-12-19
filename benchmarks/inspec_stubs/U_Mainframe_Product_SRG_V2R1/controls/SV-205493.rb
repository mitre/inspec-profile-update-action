control 'SV-205493' do
  title 'The Mainframe Product must verify users are authenticated with an individual authenticator prior to using a group authenticator.'
  desc 'To assure individual accountability and prevent unauthorized access, application users must be individually identified and authenticated. 

Individual accountability mandates that each user is uniquely identified. A group authenticator is a shared account or some other form of authentication that allows multiple unique individuals to access the application using a single account. 

If an application allows or provides for group authenticators, it must first individually authenticate users prior to implementing group authenticator functionality. 

Some applications may not have the need to provide a group authenticator; this is considered a matter of application design. In those instances where the application design includes the use of a group authenticator, this requirement will apply.

There may also be instances when specific user actions need to be performed on the information system without unique user identification or authentication. An example of this type of access is a web server which contains publicly releasable information.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account management configurations.

If the Mainframe Product is configured to require users to authenticate with an individual authenticator prior to using a group authenticator, this is not a finding'
  desc 'fix', 'Configure the Mainframe Product account management settings to require users to authenticate with an individual authenticator prior to using a group authenticator.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5759r299712_chk'
  tag severity: 'medium'
  tag gid: 'V-205493'
  tag rid: 'SV-205493r397450_rule'
  tag stig_id: 'SRG-APP-000153-MFP-000214'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-5759r299713_fix'
  tag 'documentable'
  tag legacy: ['SV-82859', 'V-68369']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
