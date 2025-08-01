control 'SV-38356' do
  title 'The audit system must alert the SA in the event of an audit processing failure.'
  desc 'An accurate and current audit trail is essential for maintaining 
a record of system activity. If the system fails, the SA must be notified and must take prompt 
action to correct the problem.

Minimally, the system must log this event and the SA will receive this notification during the 
daily system log review. If feasible, active alerting (such as e-mail or paging) should be 
employed consistent with the site’s established operations management systems and procedures.'
  desc 'check', %q("audomon" is spawned by /sbin/init.d/auditing when the system is booted with the parameter AUDITING is set to 1 in /etc/rc.config.d/auditing.

audomon monitors the capacity of the current audit trail and the file system on which the audit trail is located. audomon prints out warning messages when either capacity is approaching full. audomon also checks the audit trail and the file system against two switch points: FileSpaceSwitch (FSS) and Audit-FileSwitch (AFS). If either switch point is reached, audit recording automatically switches to an alternative audit trail. audomon also takes action, such as sending an email at the switch point if there is a task specified with the -X option. Using the -o option, audomon specifies the file where warning messages are written. By default, warning messages are sent to the console.
# cat /sbin/init.d/auditing | sed -e 's/^[ \t]*//' | tr '\011' ' ' | tr -s ' ' | grep -v "^#" | grep "audomon"

If audomon has been invoked without the "-o <file>" option (at a minimum), this is a finding.)
  desc 'fix', 'Configure the /sbin/init.d/auditing file to invoke audomon with (at a minimum) the "-o <file>" option.

Then restart auditing:
# /sbin/init.d/auditing stop
# /sbin/init.d/auditing start'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36806r2_chk'
  tag severity: 'low'
  tag gid: 'V-22374'
  tag rid: 'SV-38356r1_rule'
  tag stig_id: 'GEN002719'
  tag gtitle: 'GEN002719'
  tag fix_id: 'F-32183r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
end
