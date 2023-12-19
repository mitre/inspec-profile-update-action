control 'SV-253869' do
  title 'Tanium Comply must be configured to receive Security Content Automation Protocol (SCAP) content only from trusted sources.'
  desc 'SCAP XML documents validated by the National Institute of Standards and Technology (NIST) are provided from several possible sources such as DISA, NIST, and other nongovernment entities. These documents are used as the basis of compliance definitions leveraged to automate compliance auditing of systems. These documents are updated on different frequencies and must be downloaded manually at regular intervals and imported in order to be current. Nonapproved SCAP definitions lead to a false sense of security when evaluating an enterprise environment.'
  desc 'check', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web user interface (UI) and log on with multifactor authentication.

2. Click "Modules" on the top banner of the console.

3. Click "Comply".

4. Click the menu on the left side of the interface. Under "Standards", click "Compliance".

Verify all imported compliance benchmarks are from a documented trusted source.

If any compliance benchmark is found that does not come from a documented trusted source, this is a finding.'
  desc 'fix', '1. Using a web browser on a system that has connectivity to the Tanium application, access the Tanium application web UI and log on with multifactor authentication.

2. Click "Modules" on the top banner of the console.

3. Click "Comply".

4. Click the menu on the left side of the interface. Under "Standards", click "Compliance".

5. Delete any compliance benchmarks that come from nontrusted sources.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x'
  tag check_id: 'C-57321r842633_chk'
  tag severity: 'medium'
  tag gid: 'V-253869'
  tag rid: 'SV-253869r842635_rule'
  tag stig_id: 'TANS-SV-000052'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-57272r842634_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
