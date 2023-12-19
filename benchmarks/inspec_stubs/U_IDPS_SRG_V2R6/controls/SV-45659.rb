control 'SV-45659' do
  title 'The IDPS must fail to a secure state which maintains access control mechanisms when the IDPS hardware, software, or firmware fails on initialization/shutdown or experiences a sudden abort during normal operation.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Preserving information system state information also facilitates system restart and return to the operational mode of the organization with less disruption to mission-essential processes. 

This requirement applies to the device itself, not the network traffic. Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations. 

Since it is usually not possible to test this capability in a production environment, systems should either be validated in a testing environment or prior to installation. This requirement is usually a function of the design of the IDPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.'
  desc 'check', 'Verify the IDPS fails to a secure state which maintains access control mechanisms when the IDPS hardware, software, or firmware fails on initialization/shutdown or experiences a sudden abort during normal operation. 

If the IDPS does not fail to a secure state which maintains access control mechanisms when the IDPS hardware, software, or firmware fails on initialization/shutdown or experiences a sudden abort during normal operation, this is a finding.'
  desc 'fix', 'Configure the IDPS to fail to a secure state which maintains access control mechanisms when the IDPS hardware, software, or firmware fails on initialization/shutdown or experiences a sudden abort during normal operation.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-43025r4_chk'
  tag severity: 'medium'
  tag gid: 'V-34749'
  tag rid: 'SV-45659r3_rule'
  tag stig_id: 'SRG-NET-000235-IDPS-00169'
  tag gtitle: 'SRG-NET-000235-IDPS-00169'
  tag fix_id: 'F-39057r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
