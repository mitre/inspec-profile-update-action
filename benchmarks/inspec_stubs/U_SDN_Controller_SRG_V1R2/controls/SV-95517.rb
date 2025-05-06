control 'SV-95517' do
  title 'The SDN controller must be configured to notify the ISSO and ISSM of failed verification tests for organization-defined security functions.'
  desc 'If personnel are not notified of failed security verification tests, they will not be able to take corrective action and the unsecure condition(s) will remain. 

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

This requirement applies to applications performing security functions and the applications performing security function verification/testing.'
  desc 'check', 'Review the SDN controller configuration to determine if it is configured to notify the ISSO and ISSM of failed security verification tests. 

If the SDN controller is not configured to notify the ISSO and ISSM of failed security verification tests, this is a finding.

Note: The organization defines the system transitional states when the SDN controller will verify correct operation of the security functions.'
  desc 'fix', 'Configure the SDN controller to notify the ISSO and ISSM of failed security verification tests.

Note: DoD activities should also notify the Regional Cyber Center (RCC).

Note: The organization defines the system transitional states when the SDN controller will verify correct operation of the security functions.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80543r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80807'
  tag rid: 'SV-95517r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001085'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87661r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002694', 'CCI-002695', 'CCI-002698']
  tag nist: ['SI-5 c', 'SI-6 a', 'SI-6 b']
end
