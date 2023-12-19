control 'SV-222593' do
  title 'XML-based applications must mitigate DoS attacks by using XML filters, parser options, or gateways.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

XML-based applications are susceptible to DoS attacks due to the nature of XML parsing being processor intensive and complicated.

Best practice for parsing XML to avoid DoS include:

- Using a proven XML parser
- Using an XML gateway that provides DoS protection
- Using parser options that provide limits on recursive payloads, oversized payloads, and entity expansion.

This requirement addresses the configuration of applications to mitigate the impact of DoS attacks that have occurred or are ongoing on application availability. For each application, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Review the application architecture documentation and interview the application administrator to identify what steps have been taken to protect the XML aspect of the application from DoS attacks.

If the application does not contain or utilize XML, the requirement is not applicable.

Ask the application administrator to demonstrate how the application is configured to provide the following protections:

- Validation against recursive payloads
- Validation against oversized payloads
- Protection against XML entity expansion
- Validation against overlong element names
- Optimized configuration for maximum message throughput

If the application administrator cannot demonstrate how these protections are implemented either within the application itself or by third-party tools or utilities like an XML gateway, this is a finding.'
  desc 'fix', 'Implement:

- Validation against recursive payloads
- Validation against oversized payloads
- Protection against XML entity expansion
- Validation against overlong element names
- Optimized configuration for maximum message throughput in order to ensure DoS attacks against web services are limited.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24263r561252_chk'
  tag severity: 'medium'
  tag gid: 'V-222593'
  tag rid: 'SV-222593r561254_rule'
  tag stig_id: 'APSC-DV-002390'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-24252r561253_fix'
  tag 'documentable'
  tag legacy: ['SV-84859', 'V-70237']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
