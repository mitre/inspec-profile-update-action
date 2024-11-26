control 'SV-213578' do
  title 'The EDB Postgres Advanced Server must be configurable to overwrite audit log records, oldest first (First-In-First-Out - FIFO), in the event of unavailability of space for more audit log records.'
  desc 'It is critical that when the DBMS is at risk of failing to process audit logs as required, it take action to mitigate the failure. Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Responses to audit failure depend upon the nature of the failure mode. 

When availability is an overriding concern, approved actions in response to an audit failure are as follows: 

(i) If the failure was caused by the lack of audit record storage capacity, the DBMS must continue generating audit records, if possible (automatically restarting the audit service if necessary), overwriting the oldest audit records in a first-in-first-out manner.

(ii) If audit records are sent to a centralized collection server and communication with this server is lost or the server fails, the DBMS must queue audit records locally until communication is restored or until the audit records are retrieved manually. Upon restoration of the connection to the centralized collection server, action should be taken to synchronize the local audit data with the collection server.

Systems where availability is paramount will most likely be MAC I; the final determination is the prerogative of the application owner, subject to Authorizing Official concurrence. In any case, sufficient auditing resources must be allocated to avoid audit data loss in all but the most extreme situations.'
  desc 'check', 'If an externally managed and monitored partition or logical volume that can be grown dynamically is being used for logging, this is not a finding.  

If PPAS is auditing to a directory that is not being actively checked for availability of disk space, and if logrotate is not configured to rotate logs based on the size of the audit log directory with oldest logs being replaced by newest logs, this is a finding.'
  desc 'fix', %q(Determine the max size of your audit log directory.  For this fix, we will assume that the audit log directory has a max size of 100MB.  Divide the max size of the directory by 10 to determine the size of your log files for rotation.  Perform the following steps to ensure that the audit log directory is never more than 90% full and new logs always replace the oldest logs:

1)  Add the following to the bottom of the /etc/logrotate.conf file:

<postgresql data directory>/edb_audit/audit.csv {
    size 10M
    dateext
    dateformat .%Y-%m-%d.%s
    copytruncate
    rotate 8
}
(The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)

2)  Create the file /etc/cron.hourly/logrotate with these contents:

#!/bin/sh
/usr/sbin/logrotate /etc/logrotate.conf
EXITVALUE=$?
if [ $EXITVALUE != 0 ]; then
    /usr/bin/logger -t logrotate "ALERT exited abnormally with [$EXITVALUE]"
fi
exit 0

3)  Issue these SQL statements:

ALTER SYSTEM SET edb_audit_filename = 'audit';
SELECT pg_reload_conf();)
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14800r290046_chk'
  tag severity: 'high'
  tag gid: 'V-213578'
  tag rid: 'SV-213578r508024_rule'
  tag stig_id: 'PPS9-00-002400'
  tag gtitle: 'SRG-APP-000109-DB-000321'
  tag fix_id: 'F-14798r290047_fix'
  tag 'documentable'
  tag legacy: ['SV-83515', 'V-68911']
  tag cci: ['CCI-000140']
  tag nist: ['AU-5 b']
end
