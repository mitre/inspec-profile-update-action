control 'SV-234360' do
  title 'The UEM server must ensure users are authenticated with an individual authenticator prior to using a group authenticator.'
  desc 'To ensure individual accountability and prevent unauthorized access, application users must be individually identified and authenticated. 

Individual accountability mandates that each user is uniquely identified. A group authenticator is a shared account or some other form of authentication that allows multiple unique individuals to access the application using a single account. 

If an application allows or provides for group authenticators, it must first individually authenticate users prior to implementing group authenticator functionality. 

Some applications may not have the need to provide a group authenticator; this is considered a matter of application design. In those instances where the application design includes the use of a group authenticator, this requirement will apply.

There may also be instances when specific user actions need to be performed on the information system without unique user identification or authentication. An example of this type of access is a web server which contains publicly releasable information. 

'
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server ensures users are authenticated with an individual authenticator prior to using a group authenticator.

If the UEM server does not ensure users are authenticated with an individual authenticator prior to using a group authenticator, this is a finding.'
  desc 'fix', 'Configure the UEM server to ensure users are authenticated with an individual authenticator prior to using a group authenticator.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37545r614090_chk'
  tag severity: 'medium'
  tag gid: 'V-234360'
  tag rid: 'SV-234360r617406_rule'
  tag stig_id: 'SRG-APP-000153-UEM-000087'
  tag gtitle: 'SRG-APP-000153'
  tag fix_id: 'F-37510r614091_fix'
  tag satisfies: ['FIA \nReference:PP-MDM-414003']
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
