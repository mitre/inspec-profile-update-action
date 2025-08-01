control 'SV-253728' do
  title 'MariaDB must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity.'
  desc 'Organizations are required to use a central log management system, so, under normal conditions, the audit space allocated to the DBMS on its own server will not be an issue. However, space will still be required on the MariaDB server for audit records in transit, and, under abnormal conditions, this could fill up. Since a requirement exists to halt processing upon audit failure, a service outage would result.

If support personnel are not notified immediately upon storage volume utilization reaching 75 percent, they are unable to plan for storage capacity expansion. 

The appropriate support staff include, at a minimum, the ISSO and the DBA/SA.'
  desc 'check', 'Review OS, or third-party logging application settings to determine whether a warning will be provided when 75 percent of DBMS audit log storage capacity is reached.

If no warning will be provided, this is a finding.'
  desc 'fix', %q(Configure the system to notify appropriate support staff immediately upon storage volume utilization reaching 75 percent.

MariaDB does not monitor storage, however, it is possible to monitor storage with a script.

##### Example Monitoring Script

#!/bin/bash

DATADIR=/var/lib/psql/mysql
CURRENT=$(df ${DATADIR?} | grep / | awk '{ print $5}' | sed 's/%//g')
THRESHOLD=75

if [ "$CURRENT" -gt "$THRESHOLD" ] ; then
mail -s 'Disk Space Alert' mail@support.com << EOF
The data directory volume is almost full. Used: $CURRENT
%EOF
fi

Schedule this script in cron to run around the clock.)
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57180r841707_chk'
  tag severity: 'medium'
  tag gid: 'V-253728'
  tag rid: 'SV-253728r841709_rule'
  tag stig_id: 'MADB-10-007400'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-57131r841708_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
