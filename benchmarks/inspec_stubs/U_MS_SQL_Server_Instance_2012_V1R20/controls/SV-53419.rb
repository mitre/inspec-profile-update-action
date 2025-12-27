control 'SV-53419' do
  title 'SQL Server must restrict access to system tables, other configuration information, and metadata to DBAs and other authorized users.'
  desc 'The principle of Least Privilege must be applied to the ability of users to access system tables, system management information, other configuration information, and metadata.  Unauthorized access to this data could result in unauthorized changes to database objects, access controls, or SQL Server configuration.  Only database administrators and other authorized users must be allowed such access.

To aid in tracking and administering such permissions, individual logins must not be directly granted permissions or built-in server roles.  Instead, user-defined server roles must be created, with the permissions and built-in server roles granted to them; the individual logins must be assigned to the appropriate user-defined server roles.

The built-in server role "sysadmin" is a partial exception.  This cannot be granted to a user-defined role, only to a login account.  Most (not necessarily all) database administrators will need to be members of sysadmin.  Without this, most DBCC commands and the system stored procedures/functions listed below are unavailable.  The users who require such access must be documented and approved.  

In addition, if the site uses backup-restore software that connects to SQL Server via the Virtual Device Interface (VDI), the account used by that software must have the sysadmin role.  (See Microsoft Knowledge Base article 2926557, http://support.microsoft.com/kb/2926557).  If this applies, it must be documented and approved.

Stored procedures/functions available only to the sysadmin role:
fn_yukonsecuritymodelrequired
sp_add_agent_parameter
sp_add_agent_profile
sp_adddatatype
sp_adddistributiondb
sp_adddistributor
sp_addqreader_agent
sp_addsubscriber
sp_addsubscriber_schedule
sp_addtabletocontents
sp_attachsubscription
sp_cdc_cleanup_change_table
sp_cdc_disable_db
sp_cdc_disable_table
sp_cdc_drop_job
sp_cdc_enable_db
sp_cdc_enable_table
sp_cdc_restoredb
sp_cdc_vupgrade
sp_certify_removable
sp_change_agent_parameter
sp_change_agent_profile
sp_change_subscription_properties
sp_change_users_login
sp_changedistpublisher
sp_changedistributiondb
sp_changedistributor_password
sp_changedistributor_property
sp_changemergesubscription
sp_changeqreader_agent
sp_changereplicationserverpasswords
sp_changesubscriptiondtsinfo
sp_checkinvalidivarticle
sp_copysubscription
sp_create_removable
sp_cycle_errorlog
sp_dbcmptlevel
sp_dbmmonitoraddmonitoring
sp_dbmmonitorchangealert
sp_dbmmonitordropalert
sp_dbmmonitordropmonitoring
sp_dbmmonitorhelpalert
sp_dbmmonitorhelpmonitoring
sp_dbmmonitorresults
sp_dbmmonitorupdate
sp_dbremove
sp_drop_agent_parameter
sp_drop_agent_profile
sp_dropdatatypemapping
sp_dropdistpublisher
sp_dropdistributiondb
sp_dropdistributor
sp_dropmergepullsubscription
sp_droppullsubscription
sp_dropsubscriber
sp_dsninfo
sp_enumdsn
sp_flush_commit_table_on_demand
sp_generate_agent_parameter
sp_get_distributor
sp_get_Oracle_publisher_metadata
sp_getagentparameterlist
sp_getdefaultdatatypemapping
sp_grant_publication_access
sp_help_agent_default
sp_help_agent_parameter
sp_help_agent_profile
sp_helpdistpublisher
sp_helpdistributor
sp_helpmergesubscription
sp_helpqreader_agent
sp_helpreplicationdboption
sp_identitycolumnforreplication
sp_IHValidateRowFilter
sp_IHXactSetJob
sp_link_publication
sp_monitor
sp_MSadd_distribution_agent
sp_MSadd_logreader_agent
sp_MSadd_merge_agent
sp_MSadd_snapshot_agent
sp_MSadd_subscriber_schedule
sp_MSadd_tracer_history
sp_MSadd_tracer_token
sp_MScdc_cleanup_job
sp_MScdc_db_ddl_event
sp_MScdc_ddl_event
sp_MSchange_distribution_agent_properties
sp_MSchange_logreader_agent_properties
sp_MSchange_merge_agent_properties
sp_MSchange_snapshot_agent_properties
sp_MSchangedynamicsnapshotjobatdistributor
sp_MSchangedynsnaplocationatdistributor
sp_MScheck_pull_access
sp_MScleanupmergepublisher_internal
sp_MSclear_dynamic_snapshot_location
sp_MScreate_dist_tables
sp_MSdbuserpriv
sp_MSdeletefoldercontents
sp_MSdrop_6x_replication_agent
sp_MSdrop_merge_agent
sp_MSdrop_snapshot_dirs
sp_MSdropmergedynamicsnapshotjob
sp_MSdynamicsnapshotjobexistsatdistributor
sp_MSenumallpublications
sp_MSfetchAdjustidentityrange
sp_MSfix_6x_tasks
sp_MSforce_drop_distribution_jobs
sp_MSget_agent_names
sp_MSget_jobstate
sp_MSget_oledbinfo
sp_MSget_publication_from_taskname
sp_MSgetdbversion
sp_MSgetmaxsnapshottimestamp
sp_MShelp_repl_agent
sp_MShelp_replication_status
sp_MShelp_snapshot_agent
sp_MShelpconflictpublications
sp_MShelpdynamicsnapshotjobatdistributor
sp_MShelplogreader_agent
sp_MShelpsnapshot_agent
sp_MShelptranconflictcounts
sp_MSinit_publication_access
sp_MSreinit_failed_subscriptions
sp_MSremoveoffloadparameter
sp_MSrepl_backup_complete
sp_MSrepl_backup_start
sp_MSrepl_createdatatypemappings
sp_MSrepl_dropdatatypemappings
sp_MSrepl_enumarticlecolumninfo
sp_MSrepl_enumpublications
sp_MSrepl_enumpublishertables
sp_MSrepl_enumsubscriptions
sp_MSrepl_enumtablecolumninfo
sp_MSrepl_getdistributorinfo
sp_MSrepl_startup_internal
sp_MSreplagentjobexists
sp_MSreplcheck_permission
sp_MSreplcheck_pull
sp_MSreplcheck_subscribe
sp_MSreplcheck_subscribe_withddladmin
sp_MSreplcopyscriptfile
sp_MSreplremoveuncdir
sp_MSsetalertinfo
sp_MSSetServerProperties
sp_MSsetupnosyncsubwithlsnatdist
sp_MSsetupnosyncsubwithlsnatdist_cleanup
sp_MSsetupnosyncsubwithlsnatdist_helper
sp_MSstartdistribution_agent
sp_MSstartmerge_agent
sp_MSstartsnapshot_agent
sp_MSstopdistribution_agent
sp_MSstopmerge_agent
sp_MSstopsnapshot_agent
sp_MSupdate_agenttype_default
sp_oledbinfo
sp_procoption
sp_removedbreplication
sp_removesrvreplication
sp_replication_agent_checkup
sp_replicationdboption
sp_resetstatus
sp_restoredbreplication
sp_SetAutoSAPasswordAndDisable
sp_setdefaultdatatypemapping
sp_updatestats
sp_validatelogins
sp_vupgrade_mergeobjects
sp_vupgrade_replication
sp_vupgrade_replsecurity_metadata
xp_repl_convert_encrypt_sysadmin_wrapper'
  desc 'check', "Use SQL Server and system documentation to determine privilege assignment of user-defined roles.

Determine which user-defined roles grant privileges to system tables and configuration data stored in SQL Server.

For each Login:

In SQL Server Management Studio, Object Explorer, expand <SQL Server instance> >> Security >> Logins >> Right-click <login account name> >> Properties >> User >> Securables.

If any item in the Explicit Permissions listing, for each highlighted item that exists in the Securables listing, indicates direct permission access, and that permission is anything other than Connect SQL, this is a finding.

Navigate from Securables to Server Roles.

If any Server Roles are checked from the following list, indicating direct permission access, this is a finding:
bulkadmin
dbcreator
diskadmin
processadmin
securityadmin
serveradmin
setupadmin

If the sysadmin server role is checked, review system documentation to determine whether this login's need for the sysadmin role is documented and approved. If it is not, this is a finding.

If any user-defined server roles with system table or configuration data privileges are checked, review system documentation to determine whether this login's need for the role is documented and approved. If it is not, this is a finding.

Navigate from Server Roles to User Mapping. Select in turn each entry where the User column is non-blank. If any Database Roles are checked from the following list, indicating direct permission access, this is a finding:
db_accessadmin
db_backupoperator
db_datareader
db_datawriter
db_ddladmin
db_denydatareader
db_denydatawriter
db_owner
db_securityadmin"
  desc 'fix', 'If necessary memberships in the sysadmin role are not documented or not approved, document them and obtain approval.

If unnecessary memberships in the sysadmin role are documented, remove them from the documentation.

Remove all direct access permissions and unauthorized permissions as required using the below instructions:

In SQL Server Management Studio, Object Explorer, expand  <SQL Server instance> >> Security >> Logins >> Right-click <user account name> >> Properties >> User >> Securables.

Remove Securables permissions from user account.

Navigate from Securables to Server Roles.

Remove Server Roles permissions from user account.

Navigate from Server Roles to Users Mapping.

Remove direct permissions on db_accessadmin, db_backupoperator, db_datareader, db_datawriter, db_ddladmin, db_denydatareader, db_denydatawriter, db_owner, and db_securityadmin from user account.'
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47661r8_chk'
  tag severity: 'medium'
  tag gid: 'V-41044'
  tag rid: 'SV-53419r5_rule'
  tag stig_id: 'SQL2-00-009400'
  tag gtitle: 'SRG-APP-000062-DB-000016'
  tag fix_id: 'F-46343r5_fix'
  tag cci: ['CCI-000366', 'CCI-002220']
  tag nist: ['CM-6 b', 'AC-5 b']
end
