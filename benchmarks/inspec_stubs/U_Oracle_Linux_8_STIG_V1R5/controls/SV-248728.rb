control 'SV-248728' do
  title 'The OL 8 audit system must take appropriate action when the audit storage volume is full.'
  desc 'It is critical that when OL 8 is at risk of failing to process audit logs as required, it takes action to mitigate the failure. Audit processing failures include software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend on the nature of the failure mode. 
 
When availability is an overriding concern, other approved actions in response to an audit failure are as follows:  
 
1) If the failure was caused by the lack of audit record storage capacity, OL 8 must continue generating audit records if possible (automatically restarting the audit service if necessary) and overwriting the oldest audit records in a first-in-first-out manner. 
 
2) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, OL 8 must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.'
  desc 'check', 'Verify OL 8 takes the appropriate action when the audit storage volume is full with the following command: 
 
$ sudo grep disk_full_action /etc/audit/auditd.conf 
 
disk_full_action = HALT 
 
If the value of the "disk_full_action" option is not "SYSLOG", "SINGLE", or "HALT", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to shut down by default upon audit failure (unless availability is an overriding concern). 
 
Add or update the following line ("disk_full_action" can be set to "SYSLOG" or "SINGLE" depending on configuration) in the "/etc/audit/auditd.conf" file: 
 
disk_full_action = HALT 
 
If availability has been determined to be more important, and this decision is documented with the ISSO, configure OL 8 to notify system administration staff and ISSO staff in the event of an audit processing failure by setting the "disk_full_action" to "SYSLOG".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52162r779748_chk'
  tag severity: 'medium'
  tag gid: 'V-248728'
  tag rid: 'SV-248728r779750_rule'
  tag stig_id: 'OL08-00-030060'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag fix_id: 'F-52116r779749_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
