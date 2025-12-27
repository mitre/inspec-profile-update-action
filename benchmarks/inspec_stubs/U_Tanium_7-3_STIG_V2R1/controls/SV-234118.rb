control 'SV-234118' do
  title 'Tanium Comply must be configured to receive SCAP content only from trusted sources.'
  desc 'NIST-validated SCAP XML documents are provided from several possible sources such as DISA, NIST, and the other non-government entities. These documents are used as the basis of compliance definitions leveraged to automate compliance auditing of systems. These documents are updated on different frequencies and must be manually downloaded on regular intervals and imported in order to be current. Non-approved SCAP definitions lead to a false sense of security when evaluating an enterprise environment.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Comply".

Along the left side of the interface, click on "Benchmarks".

Select "Configuration Compliance".

Verify all imported compliance benchmarks are from a documented trusted source.

If any compliance benchmark is found that does not come from a documented trusted source, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Comply".

Along the left side of the interface, click on "Benchmarks".

Select "Configuration Compliance".

Delete any compliance benchmarks that come from non-trusted sources.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37303r610854_chk'
  tag severity: 'medium'
  tag gid: 'V-234118'
  tag rid: 'SV-234118r612749_rule'
  tag stig_id: 'TANS-SV-000052'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-37268r610855_fix'
  tag 'documentable'
  tag legacy: ['SV-102309', 'V-92207']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
