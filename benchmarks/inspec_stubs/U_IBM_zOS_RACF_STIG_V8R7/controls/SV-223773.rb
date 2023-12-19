control 'SV-223773' do
  title 'IBM z/OS NOBUFFS in SMFPRMxx must be properly set (default is MSG).'
  desc 'It is critical that when the operating system is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

When availability is an overriding concern, other approved actions in response to an audit failure are as follows: 

If the failure was caused by the lack of audit record storage capacity, the operating system must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the operating system must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation. Determine proper SMFPRMxx member in SYS1.PARMLIB.

If NOBUFFS is set to "HALT", this is not a finding.

Note: If availability is an overriding concern NOBUFFS can be set to MSG.'
  desc 'fix', 'Configure NOBUFFS to "HALT" unless availability is an overriding concern then NOBUFFS can be set to MSG.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25446r515007_chk'
  tag severity: 'medium'
  tag gid: 'V-223773'
  tag rid: 'SV-223773r604139_rule'
  tag stig_id: 'RACF-OS-000170'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag fix_id: 'F-25434r515008_fix'
  tag 'documentable'
  tag legacy: ['V-98253', 'SV-107357']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
