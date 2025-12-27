control 'SV-80421' do
  title 'Trend Deep Security must isolate security functions from non-security functions.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions. 

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. 

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles. Implementation may include isolation of memory space and libraries. Applications restrict access to security functions through the use of access control mechanisms and by implementing least privilege capabilities.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure security functions are isolated from non-security functions.

In order to restrict access to security functions through the use of access control mechanisms, least privilege capabilities must be enforced within the Deep Security, “User management” settings.

If role-based access controls are not enforced within the Administration >> User management >> Roles, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to isolate security functions from non-security functions.

Configure role-based access controls for least privileged accounts within the Administration >> User management >> Roles.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66579r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65931'
  tag rid: 'SV-80421r1_rule'
  tag stig_id: 'TMDS-00-000180'
  tag gtitle: 'SRG-APP-000233'
  tag fix_id: 'F-72007r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
