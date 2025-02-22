control 'SV-223550' do
  title 'IBM z/OS NOBUFFS in SMFPRMxx must be properly set (Default is MSG).'
  desc 'It is critical that when the operating system is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

When availability is an overriding concern, other approved actions in response to an audit failure are as follows: 

1) If the failure was caused by the lack of audit record storage capacity, the operating system must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

2) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the operating system must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Refer to IEASYS00 member in SYS1.PARMLIB Concatenation. Determine proper SMFPRMxx member in SYS1.PARMLIB.

If NOBUFFS is set to HALT, this is not a finding.

Note: If availability is an overriding concern NOBUFFS can be set to MSG.'
  desc 'fix', 'Configure NOBUFFS to HALT unless availability is an overriding concern then NOBUFFS can be set to MSG.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25223r500785_chk'
  tag severity: 'medium'
  tag gid: 'V-223550'
  tag rid: 'SV-223550r533198_rule'
  tag stig_id: 'ACF2-OS-000140'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag fix_id: 'F-25211r500786_fix'
  tag 'documentable'
  tag legacy: ['V-97805', 'SV-106909']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
