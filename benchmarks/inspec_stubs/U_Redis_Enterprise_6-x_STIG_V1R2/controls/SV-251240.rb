control 'SV-251240' do
  title 'Redis Enterprise DBMS must fail to a secure state if system initialization fails, shutdown fails, or aborts fail.'
  desc %q(Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. 

Databases must fail to a known consistent state. Transactions must be successfully completed or rolled back.

All data is stored and managed exclusively in either RAM or RAM + Flash Memory (Redis on Flash) and therefore, is at risk of being lost upon a process or server failure. As Redis Enterprise Software is not just a caching solution, but also a full-fledged database, persistence to disk is critical. Therefore, Redis Enterprise Software supports persisting data to disk on a per-database basis.

Append Only File (AOF) is a continuous writing of data to disk Snapshot. It is not a replacement for backups but should be done in addition to backups. 

AOF writes the latest "write" commands into a file either every second or during every write. It resembles a traditional RDBMS's redo log. This file can later be replayed to recover from a crash.

To ensure data availability, Redis Enterprise Software must be implemented in, at a minimum, a three-node cluster. A three-node cluster can withstand one node failure without data loss. If more than one node is lost in a three-node cluster and persistence is not enabled, then data loss is to be expected.

The Append Only File is a persistence mode that provides much better durability. For instance, using the default data fsync policy, Redis can lose just one second of writes in a dramatic event like a server power outage, or a single write if something goes wrong with the Redis process itself, but the operating system is still running correctly. AOF and RDB persistence can be enabled at the same time without problems. If the AOF is enabled on startup Redis will load the AOF, that is the file with the better durability guarantees. Check http://redis.io/topics/persistence for more information.

Redis Labs additionally recommends using the wait command. Review the wait command at: https://redis.io/commands/wait and determine if this meets organizational needs.)
  desc 'check', '1. In the console UI, click the databases tab.
2. For each listed database, click it and select configuration.
3. Verify that "Persistence" is set to: "Append Only File (AOF) - fsync every write".

If the setting is not configured or not documented to be set differently, this is a finding.

4. For each listed database, click it and select configuration.
5. Verify "Replication" is set enabled.

If the setting is not configured or not documented to be set differently, this is a finding.'
  desc 'fix', 'To enable persistence and replication in the Redis Enterprise UI, click the databases tab. For each database that requires reconfiguration, click it and select configuration. Ensure that the replication box is checked as well as the desired persistence level.

Edit the parameters necessary to meet the desired organizational needs.'
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54675r804908_chk'
  tag severity: 'medium'
  tag gid: 'V-251240'
  tag rid: 'SV-251240r804910_rule'
  tag stig_id: 'RD6X-00-010600'
  tag gtitle: 'SRG-APP-000225-DB-000153'
  tag fix_id: 'F-54629r804909_fix'
  tag 'documentable'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']
end
