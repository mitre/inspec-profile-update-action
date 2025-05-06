control 'SV-252976' do
  title 'TOSS must take appropriate action when an audit processing failure occurs.'
  desc 'It is critical that when the operating system is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode.

When availability is an overriding concern, other approved actions in response to an audit failure are as follows: 

1) If the failure was caused by the lack of audit record storage capacity, the operating system must continue generating audit records if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

2) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the operating system must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Verify TOSS takes the appropriate action when an audit processing failure occurs.

Check that TOSS takes the appropriate action when an audit processing failure occurs with the following command:

$ sudo grep disk_error_action /etc/audit/auditd.conf

disk_error_action = HALT

If the value of the "disk_error_action" option is not "SYSLOG", "SINGLE", or "HALT", or the line is commented out, ask the system administrator to indicate how the system takes appropriate action when an audit process failure occurs. If there is no evidence of appropriate action, this is a finding.'
  desc 'fix', 'Configure TOSS to shut down by default upon audit failure (unless availability is an overriding concern).

Add or update the following line (depending on configuration "disk_error_action" can be set to "SYSLOG" or "SINGLE" depending on configuration) in "/etc/audit/auditd.conf" file:

disk_error_action = HALT

If availability has been determined to be more important, and this decision is documented with the ISSO, configure the operating system to notify system administration staff and ISSO staff in the event of an audit processing failure by setting the "disk_error_action" to "SYSLOG."'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56429r824250_chk'
  tag severity: 'medium'
  tag gid: 'V-252976'
  tag rid: 'SV-252976r824252_rule'
  tag stig_id: 'TOSS-04-030090'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag fix_id: 'F-56379r824251_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
