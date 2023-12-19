control 'SV-86089' do
  title 'The CA API Gateway must check the validity of all data inputs except those specifically identified by the organization.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid input is one of the primary methods employed when attempting to compromise an application.

Network devices with the functionality to perform application layer inspection may be leveraged to validate data content of network communications. Checking the valid syntax and semantics of information system inputs (e.g., character set, length, numerical range, and acceptable values) verifies that inputs match specified definitions for format and content. Software typically follows well-defined protocols that use structured messages (i.e., commands or queries) to communicate between software modules or system components. Structured messages can contain raw or unstructured data interspersed with metadata or control information. If network elements use attacker-supplied inputs to construct structured messages without properly encoding such messages, the attacker could insert malicious commands or special characters that can cause the data to be interpreted as control information or metadata. Consequently, the module or component that receives the tainted output will perform the wrong operations or otherwise interpret the data incorrectly. Pre-screening inputs prior to passing to interpreters prevents the content from being unintentionally interpreted as commands. Input validation helps to ensure accurate and correct inputs and prevent attacks such as cross-site scripting and a variety of injection attacks.

The CA API Gateway must validate both XML and JSON schemas to verify valid inputs from a client requesting Registered Services. This helps to prevent against XDoS attacks and parameter tampering, which in turn helps to prevent the injection of malicious scripts or content into the request."
  desc 'check', 'Open the CA API Gateway - Policy Manager and double-click all Registered Services required to validate inputs. 

Verify that either the "Validate XML Schema" or "Validate JSON Schema" Assertions have been added to the policies and that they have been configured in accordance with organizational requirements. 

If they have not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and double-click each of the Registered Services required to validate inputs that do not include a "Validate XML Schema" or Validate JSON Schema" Assertion. 

Add either the "Validate XML Schema" or "Validate JSON Schema" Assertions and configure in accordance with organizational requirements.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71855r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71465'
  tag rid: 'SV-86089r1_rule'
  tag stig_id: 'CAGW-GW-000840'
  tag gtitle: 'SRG-NET-000401-ALG-000127'
  tag fix_id: 'F-77785r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
