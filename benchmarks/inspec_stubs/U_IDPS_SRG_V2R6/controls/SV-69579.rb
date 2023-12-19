control 'SV-69579' do
  title 'In the event of a logging failure, caused by loss of communications with the central logging server, the IDPS must queue audit records locally until communication is restored or until the audit records are retrieved manually or using automated synchronization tools.'
  desc 'It is critical that when the IDPS is at risk of failing to process audit logs as required, it take action to mitigate the failure.

Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure.

The IDPS performs a critical security function, so its continued operation is imperative. Since availability of the IDPS is an overriding concern, shutting down the system in the event of an audit failure should be avoided, except as a last resort. The SYSLOG protocol does not support automated synchronization, however this functionality may be provided by Network Management Systems (NMSs) which are not within the scope of this SRG.'
  desc 'check', 'Verify the IDPS, in the event of a logging failure caused by loss of communications with the central logging server, queues audit records locally until communication is restored or until the audit records are retrieved manually or using automated synchronization tools.

In the event of a logging failure caused by loss of communications with the central logging server, if the IDPS does not queue audit records locally until communication is restored or until the audit records are retrieved manually or using automated synchronization tools, this is a finding.'
  desc 'fix', 'Configure the IDPS, in the event of a logging failure caused by loss of communications with the central logging server, to queue audit records locally until communication is restored or until the audit records are retrieved manually or using automated synchronization tools.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55955r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55333'
  tag rid: 'SV-69579r1_rule'
  tag stig_id: 'SRG-NET-000089-IDPS-00010'
  tag gtitle: 'SRG-NET-000089-IDPS-00010'
  tag fix_id: 'F-60199r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
