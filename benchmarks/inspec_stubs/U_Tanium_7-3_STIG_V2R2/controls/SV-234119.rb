control 'SV-234119' do
  title 'Tanium Comply must be configured to receive OVAL feeds only from trusted sources.'
  desc 'OVAL XML documents are provided from several possible sources such as the CIS open source repository, or any number of vendor/3rd party paid repositories. These documents are used to automate the passive validation of vulnerabilities on systems and therefore require a reasonable level of confidence in their origin. Non-approved OVAL definitions lead to a false sense of security when evaluating an enterprise environment.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Comply".

Along the left side of the interface, click on "Benchmarks".

Select "Vulnerability".

Verify all imported vulnerability sources are from a documented trusted source.

If any vulnerability sources found do not match a documented trusted source, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Application, access the Tanium Application web user interface (UI).

Log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Comply".

Along the left side of the interface, click on "Benchmarks".

Select "Vulnerability".

Delete any vulnerability sources, which are configured to non-trusted sources, or reconfigured to point to trusted sources.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37304r610857_chk'
  tag severity: 'medium'
  tag gid: 'V-234119'
  tag rid: 'SV-234119r612749_rule'
  tag stig_id: 'TANS-SV-000053'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-37269r610858_fix'
  tag 'documentable'
  tag legacy: ['SV-102311', 'V-92209']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
