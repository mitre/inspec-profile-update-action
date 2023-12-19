control 'SV-222590' do
  title 'The application must isolate security functions from non-security functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Applications restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify if the application utilizes access controls.

Commonly employed access controls include Role-Based Access Controls (RBAC), Access Control Lists (ACL) and Mandatory Access Controls (MAC).

Ensure the application utilizes a control structure that is capable of protecting security assets such as policy and configuration settings from unauthorized modification.

If the application does not protect security functions that enforce security policy and protect security configuration settings, this is a finding.'
  desc 'fix', 'Implement controls within the application that limits access to security configuration functionality and isolates regular application function from security-oriented function.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24260r493678_chk'
  tag severity: 'medium'
  tag gid: 'V-222590'
  tag rid: 'SV-222590r508029_rule'
  tag stig_id: 'APSC-DV-002360'
  tag gtitle: 'SRG-APP-000233'
  tag fix_id: 'F-24249r493679_fix'
  tag 'documentable'
  tag legacy: ['SV-84853', 'V-70231']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
