control 'SV-215797' do
  title 'The BIG-IP Core implementation must be configured to check the validity of all data inputs except those specifically identified by the organization.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior potentially leading to an application or information system compromise. Invalid input is one of the primary methods employed when attempting to compromise an application.

Network devices with the functionality to perform application layer inspection may be leveraged to validate data content of network communications. Checking the valid syntax and semantics of information system inputs (e.g., character set, length, numerical range, and acceptable values) verifies that inputs match specified definitions for format and content. Software typically follows well-defined protocols that use structured messages (i.e., commands or queries) to communicate between software modules or system components. Structured messages can contain raw or unstructured data interspersed with metadata or control information. If network elements use attacker-supplied inputs to construct structured messages without properly encoding such messages, then the attacker could insert malicious commands or special characters that can cause the data to be interpreted as control information or metadata. Consequently, the module or component that receives the tainted output will perform the wrong operations or otherwise interpret the data incorrectly. Pre-screening inputs prior to passing to interpreters prevents the content from being unintentionally interpreted as commands. Input validation helps to ensure accurate and correct inputs and prevent attacks such as cross-site scripting and a variety of injection attacks.

This requirement applies to gateways and firewalls that perform content inspection or have higher-layer proxy functionality.

Note: A limitation of ~200 policies per cluster currently exists on the BIG-IP Core.  If this requirement cannot be met due to this limitation, documentation from the AO is required."
  desc 'check', 'If the BIG-IP Core does not perform content inspection as part of the traffic management functionality for virtual servers, this is not applicable.

When content inspection is performed as part of the traffic management functionality, verify the BIG-IP Core is configured to check the validity of all data inputs except those specifically identified by the organization.

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an ASM policy to check the validity of all data inputs except those specifically identified by the organization.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "Application Security Policy" is Enabled and "Policy" is set to use an ASM policy to check the validity of all data inputs except those specifically identified by the organization.

If the BIG-IP Core is not configured to check the validity of all data inputs except those specifically identified by the organization, this is a finding.'
  desc 'fix', 'If the BIG-IP Core performs content inspection as part of the traffic management functionality, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP ASM module to check the validity of all data inputs except those specifically identified by the organization.

Apply ASM policy to the applicable Virtual Server(s) in BIG-IP LTM module to check the validity of all data inputs except those specifically identified by the organization.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16989r291204_chk'
  tag severity: 'medium'
  tag gid: 'V-215797'
  tag rid: 'SV-215797r557356_rule'
  tag stig_id: 'F5BI-LT-000261'
  tag gtitle: 'SRG-NET-000401-ALG-000127'
  tag fix_id: 'F-16987r291205_fix'
  tag 'documentable'
  tag legacy: ['SV-74805', 'V-60375']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
