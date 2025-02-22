control 'SV-222608' do
  title 'The application must not be vulnerable to XML-oriented attacks.'
  desc 'Extensible Markup Language (XML) is widely employed in web technology and applications like web services (SOAP, REST, and WSDL) and is also used for configuration files. XML vulnerability examples include XML injection, XML Spoofing, XML-based Denial of Service attacks and information disclosure attacks.

When utilizing XML, web applications must take steps to ensure they are addressing XML-related security issues. This is accomplished by choosing well-designed application components, building application code that follows security best practices and by patching application components when vulnerabilities are identified.

XML firewalls or gateways may be employed to assist in protecting applications by controlling access to XML-based applications, filtering XML content, rate-limiting requests, and validating XML traffic.'
  desc 'check', 'Review the application documentation, the application architecture and interview the application administrator.

Identify any XML-based web services or XML functionality performed by the application.

Determine if an XML firewall is deployed to protect application from XML-related attacks.

If the application does not process XML, the requirement is not applicable.

Review the latest application vulnerability assessment and verify the scan was configured to test for XML-related vulnerabilities and security issues.

Examples include but are not limited to:

XML Injection
XML related Denial of Service
XPATH injection
XML Signature attacks
XML Spoofing

If an XML firewall is deployed, request configuration information regarding the application and validate the firewall is configured to protect the application.

If the vulnerability scan is not configured to scan for XML-oriented vulnerabilities, if no scan results exist, or if the XML firewall is not configured to protect the application, this is a finding.'
  desc 'fix', 'Design the application to utilize components that are not vulnerable to XML attacks.

Patch the application components when vulnerabilities are discovered.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24278r493732_chk'
  tag severity: 'high'
  tag gid: 'V-222608'
  tag rid: 'SV-222608r508029_rule'
  tag stig_id: 'APSC-DV-002550'
  tag gtitle: 'SRG-APP-000251'
  tag fix_id: 'F-24267r493733_fix'
  tag 'documentable'
  tag legacy: ['SV-84891', 'V-70269']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
