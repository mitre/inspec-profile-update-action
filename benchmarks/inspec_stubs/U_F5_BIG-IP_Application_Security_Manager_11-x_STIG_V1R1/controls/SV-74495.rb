control 'SV-74495' do
  title 'The BIG-IP ASM module must check the validity of all data inputs except those specifically identified by the organization.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior potentially leading to an application or information system compromise. Invalid input is one of the primary methods employed when attempting to compromise an application.

Network devices with the functionality to perform application layer inspection may be leveraged to validate data content of network communications. Checking the valid syntax and semantics of information system inputs (e.g., character set, length, numerical range, and acceptable values) verifies that inputs match specified definitions for format and content. Software typically follows well-defined protocols that use structured messages (i.e., commands or queries) to communicate between software modules or system components. Structured messages can contain raw or unstructured data interspersed with metadata or control information. If network elements use attacker-supplied inputs to construct structured messages without properly encoding such messages, then the attacker could insert malicious commands or special characters that can cause the data to be interpreted as control information or metadata. Consequently, the module or component that receives the tainted output will perform the wrong operations or otherwise interpret the data incorrectly. Pre-screening inputs prior to passing to interpreters prevents the content from being unintentionally interpreted as commands. Input validation helps to ensure accurate and correct inputs and prevents attacks such as cross-site scripting and a variety of injection attacks.

This requirement applies to gateways and firewalls that perform content inspection or have higher-layer proxy functionality.

Note: A limitation of ~200 policies per cluster currently exists on the BIG-IP Core.  If this requirement cannot be met due to this limitation, documentation from the AO is required."
  desc 'check', 'If the BIG-IP ASM module is not used to support content filtering as part of the traffic management functions of the BIG-IP Core, this is not applicable.

Verify the BIG-IP ASM module is configured to check the validity of all data inputs except those specifically identified by the organization.

Navigate to the BIG-IP System manager >> Application Security >> Parameters >> Parameters List.

Select the policy for "Current Edited Policy" used for checking data inputs.

Review the parameters under the "Parameters List" section.

Verify parameters are configured to check the validity of all data inputs except those specifically identified by the organization.

If the BIG-IP ASM module is not configured to check the validity of all data inputs except those specifically identified by the organization, this is a finding.'
  desc 'fix', 'If the BIG-IP ASM module is used to support content filtering as part of the traffic management functionality of the BIG-IP Core, configure the BIG-IP ASM module to check the validity of all data inputs except those specifically identified by the organization.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP ASM 11.x'
  tag check_id: 'C-60745r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60065'
  tag rid: 'SV-74495r1_rule'
  tag stig_id: 'F5BI-AS-000261'
  tag gtitle: 'SRG-NET-000401-ALG-000127'
  tag fix_id: 'F-65475r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
