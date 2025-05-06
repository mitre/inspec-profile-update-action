control 'SV-222624' do
  title 'The ISSO must ensure active vulnerability testing is performed.'
  desc 'Use of automated scanning tools accompanied with manual testing/validation which confirms or expands on the automated test results is an accepted best practice when performing application security testing. Automated scanning tools expedite and help to standardize security testing, they can incorporate known attack methods and procedures, test for libraries and other software modules known to be vulnerable to attack and utilize a test method known as "fuzz testing". Fuzz testing is a testing process where the application is provided invalid, unexpected, or random data. Poorly designed and coded applications will become unstable or crash. Properly designed and coded applications will reject improper and unexpected data input from application clients and remain stable.

Many vulnerability scanning tools provide automated fuzz testing capabilities for the testing of web applications. All of these tools help to identify a wide range of application vulnerabilities including, but not limited to; buffer overflows, cross-site scripting flaws, denial of service format bugs and SQL injection, all of which can lead to a successful compromise of the system or result in a denial of service.

Due to changes in the production environment, it is a good practice to schedule periodic active testing of production web applications. Ideally, this will occur prior to deployment and after updates or changes to the application production environment.

It is imperative that automated scanning tools are configured properly to ensure that all of the application components that can be tested are tested. In the case of web applications, some of the application code base may be accessible on the website and could potentially be corrected by a knowledgeable system administrator. Active testing is different from code review testing in that active testing does not require access to the application source code base. A code review requires complete code base access and is normally performed by the development team.

If vulnerability testing is not conducted, there is the distinct potential that security vulnerabilities could be unknowingly introduced into the application environment.

The following website provides an overview of fuzz testing and examples:

http://www.owasp.org/index.php/Fuzzing'
  desc 'check', 'Ask the application representative to provide vulnerability test procedures and vulnerability test results.

Ask the application representative to provide the settings that were used to conduct the vulnerability testing.

Verify the automated vulnerability scanning tool was appropriately configured to assure as complete a test as possible of the application architecture components. E.g., if the application includes a web server, web server tests must be included.

If the vulnerability scan report includes informational and/or non-critical results this is not a finding.

If previously identified vulnerabilities have subsequently been resolved, this is not a finding.

If the application test procedures and test results do not include active vulnerability and fuzz testing this is a finding.

If the vulnerability scan results include critical vulnerabilities, this is a finding.

If the vulnerability scanning tests are not relevant to the architecture of the application, this is a finding.'
  desc 'fix', 'Perform active vulnerability and fuzz testing of the application.

Verify the vulnerability scanning tool is configured to test all application components and functionality.

Address discovered vulnerabilities.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24294r493780_chk'
  tag severity: 'medium'
  tag gid: 'V-222624'
  tag rid: 'SV-222624r864409_rule'
  tag stig_id: 'APSC-DV-002930'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24283r493781_fix'
  tag 'documentable'
  tag legacy: ['SV-84925', 'V-70303']
  tag cci: ['CCI-000256']
  tag nist: ['CA-2 (2)']
end
