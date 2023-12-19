control 'SV-251253' do
  title 'Security-relevant software updates to Redis Enterprise DBMS must be installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications, including database management systems, are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality, will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period used must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).

For more information, refer to:
https://docs.redislabs.com/latest/rs/installing-upgrading/upgrading/'
  desc 'check', 'To determine the current version of the software, perform the steps below:

1. Log in to the Redis Enterprise UI as an Admin user.
2. Navigate to the Cluster tab in the red banner.
3. Click on the Configuration option.
4. Find the Version number of the Cluster, Latest Redis version supported, and Latest Memcached version supported.
5. Compare to current Redis Enterprise version available.

If the organization is not following their own defined time periods to apply updates, this is a finding.'
  desc 'fix', %q(To update to the current version of the software, perform the following steps listed from the Redis Labs Enterprise site. To upgrade the Redis Enterprise Software (RS) software on a cluster, upgrade each of the nodes and then upgrade each of the databases in the cluster.

- To upgrade the cluster to v6.0, the cluster must first be on 5.4.0 or above and the databases must be running Redis 5.
- To upgrade the cluster to v5.6, the cluster must first be on 5.0.2-30 or above.
- To upgrade the cluster to v5.4, the cluster must first be on 5.0 or above.
- To upgrade the cluster to v5.2, the cluster must first be on 4.5 or above.

The upgrade process for a Redis Enterprise Software cluster is "ongoing" when the nodes in the cluster have mixed versions. The upgrade is only considered complete when all of the nodes are upgraded to the new version.

WARNING Using features from the newer version before all nodes are upgraded can produce unexpected results or cause failures in the cluster.

Upgrading a node: 
Upgrading the software on a node requires installing the RS installation package on all of the machines on which RS is installed.

WARNING: The master node must be upgraded before upgrading the other nodes. It is recommended to keep all nodes up until the upgrade is completed on all nodes. The node role is shown in the output of the rladmin status nodes command. The installation path and user cannot be changed during upgrade. Node upgrade fails if the SSL certificates were configured in version 5.0.2 or above by manually updating the certificates on the disk instead of updating them through the API. For assistance with this issue, contact Support.

Run install.sh from the directory where the media was untarred just like what is done for a new installation. The software recognizes this is an upgrade and proceeds accordingly.

As with a new installation, user must sudo or be root to do the upgrade.

To upgrade a node, run:
sudo ./install.sh

The node upgrade process restarts the services running RS, which causes a short interruption to connections to the proxy, node, and databases.

WARNING: To ensure cluster and databases' availability, it is important to upgrade the nodes one by one, and not attempt to upgrade more than one node at a time. To make sure that the node is functioning properly, run rlcheck and rladmin status extra all on the node both before and after the upgrade.

If the RS management UI is open in the browser while upgrading the nodes, make sure to refresh the browser before trying to work with the UI again.

Upgrading a database 
Some RS upgrades add support for new Redis versions. In these cases, Redis Labs recommends upgrading the databases to the new Redis version, although this is not mandatory because RS upgrades are backward compatible. RS also supports a mix of Redis database versions.

RS always supports two Redis versions. By default, new Redis databases are created with the latest version, and existing databases get upgraded to the latest version according to the instructions detailed below. If there is a desire to change the default Redis version to the previous version supported, it is recommended to use the tune cluster default_redis_version command in the rladmin CLI and set it to the previous Redis version supported.

To determine whether the Redis database versions match the latest Redis version supported by RS:
In the rladmin CLI, run the status command. If the Redis version is not the latest supported, an indication appears in the command output next to the database's status.

In the Management UI, Navigate to the Cluster >> Configuration page. The page lists the latest Redis version supported.

If the Redis database versions are older than the version supported by RS, Redis Labs recommends upgrading the Redis databases.

To upgrade the database:
- Ensure that all of the nodes in the RS cluster are upgraded. Databases cannot be upgraded before all of the nodes in the cluster are upgraded.
- In the rladmin CLI on any node in the cluster, run this command for each database: 
rladmin upgrade db <database_name | database_ID>

During the database upgrade process, the database is restarted. As a result:
For databases that have replication enabled, a failover is done before the master database restarts to make sure that there is no downtime.

For databases without replication but with persistence enabled, the database is unavailable during the restart because data is restored from the persistence file. The length of the downtime is different for each persistence option. For example, AOF usually takes longer than an RDB file.

For databases that have neither replication nor persistence enabled, the database loses all its data after it is restarted.

Upgrading Active-Active databases 
When upgrading an Active-Active (CRDB) database, the following may also be upgraded:

Protocol version - RS 5.4.2 and higher include a new CRDB protocol version to support new Active-Active features. The CRDB protocol is backward-compatible so that RS 5.4.2 CRDB instances can understand write-operations that come from instances with the older CRDB protocol, but CRDB instances with the older protocol cannot understand write-operations of instances with the newer protocol version. As a result, after upgrading the CRDB protocol on one instance, instances that were not upgraded yet cannot receive write updates from the upgraded instance. The upgraded instance receives updates from upgraded and non-upgraded instances.

Note: Upgrade all instances of a specific CRDB within a reasonable time frame to avoid temporary inconsistencies between the instances. Make sure that  all instances of a specific CRDB are upgraded before performing global operations on the CRDB, such as removing instances and adding new instances.

After upgrading an instance to use the new protocol version, it automatically receives any missing write-operations.

Feature set version: RS 5.6.0 and higher include a new feature set version to support new Active-Active features. When updating the feature set version for an Active-Active database, the feature set version is updated for all of the database instances.

To upgrade a CRDB instance:
Upgrade RS on each node in the clusters where the CRDB instances are located.

To confirm the status of the CRDB instances, run: rladmin status

The statuses of the CRDB instances on the node can indicate:
OLD REDIS VERSION
OLD CRDB PROTOCOL VERSION
OLD CRDB FEATURESET VERSION
crdb-upgrade-node

To upgrade each CRDB instance including the Redis version and CRDB protocol version, run:
rladmin upgrade db <database_name | database_ID>

If the protocol version is old, read the warning message carefully and confirm. crdb-upgrade-protocol

The CRDB instance uses the new Redis version and CRDB protocol version.

To upgrade the CRDB instance without upgrading the protocol version:
If the feature set version is old, all of the CRDB instances must be upgraded. Then, to update the feature set for each active-active database, run:
crdb-cli crdb update --crdb-guid <CRDB-GUID> --featureset-version yes

Retrieve the <CRDB-GUID> with the following command:
crdb-cli crdb list

Look for the fully qualified domain name (CLUSTER-FDQN) of the cluster and use the associated GUID.)
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54688r804947_chk'
  tag severity: 'medium'
  tag gid: 'V-251253'
  tag rid: 'SV-251253r855626_rule'
  tag stig_id: 'RD6X-00-012500'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag fix_id: 'F-54642r804948_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
