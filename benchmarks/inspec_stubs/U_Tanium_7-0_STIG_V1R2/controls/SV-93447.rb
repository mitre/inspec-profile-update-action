control 'SV-93447' do
  title 'Tanium Comply must be configured to receive OVAL feeds only from trusted sources.'
  desc 'OVAL XML documents are provided from several possible sources such as the CIS open source repository, or any number of vendor/3rd party paid repositories. These documents are used to automate the passive validation of vulnerabilities on systems and therefore require a reasonable level of confidence in their origin. Non-approved OVAL definitions lead to a false sense of security when evaluating an enterprise environment.'
  desc 'check', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web user interface (UI) and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Comply".

Along the left side of the interface, click on "Benchmarks" then "Vulnerability".

Verify all imported vulnerability sources are from a documented trusted source.

If any vulnerability sources found do not match a documented trusted source, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to Tanium, access the Tanium web UI and log on with CAC.

Click on the navigation button (hamburger menu) on the top left of the console.

Click on "Comply".

Along the left side of the interface, click on "Benchmarks" then "Vulnerability".

Delete any vulnerability sources that are configured to non-trusted sources, or reconfigured to point to a trusted sources.'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78317r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78741'
  tag rid: 'SV-93447r1_rule'
  tag stig_id: 'TANS-SV-000053'
  tag gtitle: 'SRG-APP-000039'
  tag fix_id: 'F-85483r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
