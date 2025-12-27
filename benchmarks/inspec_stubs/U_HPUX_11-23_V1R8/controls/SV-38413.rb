control 'SV-38413' do
  title 'The system must be configured to send audit records to a remote audit server.'
  desc "Audit records contain evidence that can be used in the investigation of compromised systems. To prevent this evidence from compromise, it must be sent to a separate system continuously. Methods for sending audit records include, but are not limited to, system audit tools used to send logs directly to another host or through the system's syslog service to another host."
  desc 'check', %q(The audit overflow monitor daemon (audomon) is spawned by /sbin/init.d/auditing as part of the init start-up process. The vendor (HP) recommends that a script be written to implement a long term strategy for data storage and pass it to the audomon daemon using the "-X <command>" option. <command> is executed each time audomon switches the audit trail. The means used to implement audit log transfer to a remote system will be site specific and therefore always require a manual review. 

ASK the SA if audomon is configured per the vendor's (HP) guidance to implement a long term, remote data storage strategy.)
  desc 'fix', 'The audit overflow monitor daemon (audomon) is spawned by /sbin/init.d/auditing as part of the init start-up process. Create a <command> script to implement the vendor-recommended, long term data storage strategy and pass it to the audomon daemon using the "-X <command>" option. The <command> must be  executed each time audomon switches the audit trail. 

A manual review of the <command> script is required.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36807r2_chk'
  tag severity: 'low'
  tag gid: 'V-24357'
  tag rid: 'SV-38413r1_rule'
  tag stig_id: 'GEN002870'
  tag gtitle: 'GEN002870'
  tag fix_id: 'F-32184r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECTB-1'
  tag cci: ['CCI-000136']
  tag nist: ['AU-3 (2)']
end
