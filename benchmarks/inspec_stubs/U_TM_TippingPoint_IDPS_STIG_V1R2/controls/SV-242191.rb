control 'SV-242191' do
  title 'The TPS must fail to a secure state which maintains access control mechanisms when the IDPS hardware, software, or firmware fails on initialization/shutdown or experiences a sudden abort during normal operation (also known as "Fail closed").'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Preserving information system state information also facilitates system restart and return to the operational mode of the organization with less disruption to mission-essential processes. 

This requirement applies to the device itself, not the network traffic. Abort refers to stopping a program or function before it has finished naturally. The term abort refers to both requested and unexpected terminations. 

Since it is usually not possible to test this capability in a production environment, systems should be validated either in a testing environment or prior to installation. This requirement is usually a function of the design of the TPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.'
  desc 'check', '1. In the Trend Micro SMS, navigate to "Devices". 
2. Select the device that will be modified, then select "Network Configuration". 

If any of the Intrinsic HA items state Permit All, this is a finding.'
  desc 'fix', '1. In the Trend Micro SMS, navigate to "Devices". 
2. Select the device that will be modified, then select "Network Configuration". 
3. Click each segment that is currently operational. 
   a. Click "Edit". 
   b. Under "Link Down Synchronization" select "Block All" and ensure the Link Down Synchronization Mode is "Wire" and 1 second wait time. 
   c. Select Finish.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint IDPS'
  tag check_id: 'C-45466r710114_chk'
  tag severity: 'medium'
  tag gid: 'V-242191'
  tag rid: 'SV-242191r710116_rule'
  tag stig_id: 'TIPP-IP-000260'
  tag gtitle: 'SRG-NET-000235-IDPS-00169'
  tag fix_id: 'F-45424r710115_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
