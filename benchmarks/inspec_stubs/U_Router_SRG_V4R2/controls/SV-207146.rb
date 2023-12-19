control 'SV-207146' do
  title 'The router must be configured to stop forwarding traffic upon the failure of the following actions: system initialization, shutdown, or system abort.'
  desc 'Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. Routers that fail suddenly and with no incorporated failure state planning may leave the hosting system available but with a reduced security protection capability. Preserving information system state information also facilitates system restart and return to the operational mode of the organization with less disruption to mission-essential processes.

If the router fails in an unsecure manner (open), unauthorized traffic originating externally to the enclave may enter, or the device may permit unauthorized information release. Fail secure is a condition achieved by employing information system mechanisms to ensure, in the event of a device initialization failure, a device shutdown failure, or an abort failure of the router, that it does not enter into an unsecure state where intended security properties no longer hold.

If the device fails, it must not fail in a manner that will allow unauthorized access. If the router fails for any reason, it must stop forwarding traffic altogether or maintain the configured security policies. If the device stops forwarding traffic, maintaining network availability would be achieved through device redundancy.

Since it is usually not possible to test this capability in a production environment, systems should either be validated in a testing environment or prior to installation. This requirement is usually a function of the design of the router component. Compliance can be verified by acceptance/validation processes or vendor attestation.'
  desc 'check', 'Verify the router stops forwarding traffic or maintains the configured security policies upon the failure of the following actions: system initialization, shutdown, or system abort.

If the router does not stop forwarding traffic or maintain the configured security policies upon the failure of system initialization, shutdown, or system abort, this is a finding.'
  desc 'fix', 'This is a capability that would be intrinsic to the router as a result of its development and may not be configurable.

If it is a configurable option, configure the router to stop forwarding traffic or maintain the configured security policies upon the failure of the following actions: system initialization, shutdown, or system abort.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7407r382421_chk'
  tag severity: 'medium'
  tag gid: 'V-207146'
  tag rid: 'SV-207146r604135_rule'
  tag stig_id: 'SRG-NET-000235-RTR-000114'
  tag gtitle: 'SRG-NET-000235'
  tag fix_id: 'F-7407r382422_fix'
  tag 'documentable'
  tag legacy: ['SV-70033', 'V-55779']
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
