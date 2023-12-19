control 'SV-95513' do
  title 'The SDN controller must be configured to isolate security functions from non-security functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. 

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Applications restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', 'Review the SDN controller configuration to determine whether objects and code implementing security functionality are isolated from non-security functionality objects and code. Role-based access control (RBAC) must also be configured to restrict access to all security functionality. 

If security-related objects and code are not kept separate and are not configured with RBAC access restriction, this is a finding.'
  desc 'fix', 'Configure the SDN controller to isolate objects and code implementing RBAC to restrict access to security functionality from non-security functionality objects and code.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80539r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80803'
  tag rid: 'SV-95513r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001075'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87657r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
