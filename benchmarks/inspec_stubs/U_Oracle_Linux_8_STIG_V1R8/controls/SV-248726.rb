control 'SV-248726' do
  title 'The OL 8 System must take appropriate action when an audit processing failure occurs.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. 
 
Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. 
 
This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.'
  desc 'check', 'Verify OL 8 takes the appropriate action when an audit processing failure occurs with the following command: 
 
$ sudo grep disk_error_action /etc/audit/auditd.conf 
 
disk_error_action = HALT 
 
If the value of the "disk_error_action" option is not "SYSLOG", "SINGLE", or "HALT", or the line is commented out, this is a finding.'
  desc 'fix', 'Configure OL 8 to shut down by default upon audit failure (unless availability is an overriding concern). 
 
Add or update the following line ("disk_error_action" can be set to "SYSLOG" or "SINGLE" depending on configuration) in the "/etc/audit/auditd.conf" file: 
 
disk_error_action = HALT 
 
If availability has been determined to be more important, and this decision is documented with the ISSO, configure OL 8 to notify system administration staff and ISSO staff in the event of an audit processing failure by setting the "disk_error_action" to "SYSLOG".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52160r779742_chk'
  tag severity: 'medium'
  tag gid: 'V-248726'
  tag rid: 'SV-248726r779744_rule'
  tag stig_id: 'OL08-00-030040'
  tag gtitle: 'SRG-OS-000047-GPOS-00023'
  tag fix_id: 'F-52114r779743_fix'
  tag 'documentable'
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
