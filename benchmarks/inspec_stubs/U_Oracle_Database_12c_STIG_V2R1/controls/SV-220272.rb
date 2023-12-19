control 'SV-220272' do
  title 'The DBMS must produce audit records containing sufficient information to establish where the events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content that may be necessary to satisfy the requirement of this control includes:  timestamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, file names involved, and access control or flow control rules invoked.

Without sufficient information establishing where the audit events occurred, investigation into the cause of events is severely hindered.'
  desc 'check', %q(Verify, using vendor and system documentation if necessary, that the DBMS is configured to use Oracle's auditing features, or that a third-party product or custom code is deployed and configured to satisfy this requirement.

If a third-party product or custom code is used, compare its current configuration with the audit requirements. If any of the requirements is not covered by the configuration, this is a finding.

The remainder of this Check is applicable specifically where Oracle auditing is in use.

If Standard Auditing is used:
To see if Oracle is configured to capture audit data, enter the following SQL*Plus command:

SHOW PARAMETER AUDIT_TRAIL

or the following SQL query:

SELECT * FROM SYS.V$PARAMETER WHERE NAME = 'audit_trail';

If Oracle returns the value 'NONE', this is a finding.

To confirm that Oracle audit is capturing sufficient information to establish where events occurred, perform a successful auditable action and an auditable action that results in an SQL error, and then view the results in the SYS.AUD$ table or the audit file, whichever is in use.

If no DB ID or Object Creator (standard audit) or Object Schema (unified audit) or Object Name, or the wrong values, are returned for the auditable actions just performed, this is a finding.

If no DB ID or OBJ$CREATOR or the wrong values, are returned for the auditable actions just performed, this is a finding.

If correct values for USERHOST and TERMINAL are not returned when applicable, this is a finding.

If Unified Auditing is used:
To see if Oracle is configured to capture audit data, enter the following SQL*Plus command:

SELECT * FROM V$OPTION WHERE PARAMETER = 'Unified Auditing';

If Oracle returns the value "FALSE", this is a finding.

To confirm that Oracle audit is capturing sufficient information to establish where events occurred, perform a successful auditable action and an auditable action that results in an SQL error, and then view the results in the SYS.UNIFIED_AUDIT_TRAIL view.

If no DBID or OBJECT_SCHEMA or OBJECT_NAME, or the wrong values, are returned for the auditable actions just performed, this is a finding.

If correct values for USERHOST and TERMINAL are not returned when applicable, this is a finding.

For Unified Auditing, the following view can be useful for reviewing its output:

CREATE OR REPLACE FORCE VIEW SYS.UNIFIED_AUDIT_TRAIL
(
AUDIT_TYPE,
SESSIONID,
PROXY_SESSIONID,
OS_USERNAME,
USERHOST,
TERMINAL,
INSTANCE_ID,
DBID,
AUTHENTICATION_TYPE,
DBUSERNAME,
DBPROXY_USERNAME,
EXTERNAL_USERID,
GLOBAL_USERID,
CLIENT_PROGRAM_NAME,
DBLINK_INFO,
XS_USER_NAME,
XS_SESSIONID,
ENTRY_ID,
STATEMENT_ID,
EVENT_TIMESTAMP,
ACTION_NAME,
RETURN_CODE,
OS_PROCESS,
TRANSACTION_ID,
SCN,
EXECUTION_ID,
OBJECT_SCHEMA,
OBJECT_NAME,
SQL_TEXT,
SQL_BINDS,
APPLICATION_CONTEXTS,
CLIENT_IDENTIFIER,
NEW_SCHEMA,
NEW_NAME,
OBJECT_EDITION,
SYSTEM_PRIVILEGE_USED,
SYSTEM_PRIVILEGE,
AUDIT_OPTION,
OBJECT_PRIVILEGES,
ROLE,
TARGET_USER,
EXCLUDED_USER,
EXCLUDED_SCHEMA,
EXCLUDED_OBJECT,
ADDITIONAL_INFO,
UNIFIED_AUDIT_POLICIES,
FGA_POLICY_NAME,
XS_INACTIVITY_TIMEOUT,
XS_ENTITY_TYPE,
XS_TARGET_PRINCIPAL_NAME,
XS_PROXY_USER_NAME,
XS_DATASEC_POLICY_NAME,
XS_SCHEMA_NAME,
XS_CALLBACK_EVENT_TYPE,
XS_PACKAGE_NAME,
XS_PROCEDURE_NAME,
XS_ENABLED_ROLE,
XS_COOKIE,
XS_NS_NAME,
XS_NS_ATTRIBUTE,
XS_NS_ATTRIBUTE_OLD_VAL,
XS_NS_ATTRIBUTE_NEW_VAL,
DV_ACTION_CODE,
DV_ACTION_NAME,
DV_EXTENDED_ACTION_CODE,
DV_GRANTEE,
DV_RETURN_CODE,
DV_ACTION_OBJECT_NAME,
DV_RULE_SET_NAME,
DV_COMMENT,
DV_FACTOR_CONTEXT,
DV_OBJECT_STATUS,
OLS_POLICY_NAME,
OLS_GRANTEE,
OLS_MAX_READ_LABEL,
OLS_MAX_WRITE_LABEL,
OLS_MIN_WRITE_LABEL,
OLS_PRIVILEGES_GRANTED,
OLS_PROGRAM_UNIT_NAME,
OLS_PRIVILEGES_USED,
OLS_STRING_LABEL,
OLS_LABEL_COMPONENT_TYPE,
OLS_LABEL_COMPONENT_NAME,
OLS_PARENT_GROUP_NAME,
OLS_OLD_VALUE,
OLS_NEW_VALUE,
RMAN_SESSION_RECID,
RMAN_SESSION_STAMP,
RMAN_OPERATION,
RMAN_OBJECT_TYPE,
RMAN_DEVICE_TYPE,
DP_TEXT_PARAMETERS1,
DP_BOOLEAN_PARAMETERS1,
DIRECT_PATH_NUM_COLUMNS_LOADED
)
AS
SELECT act.component,
sessionid,
proxy_sessionid,
os_user,
host_name,
terminal,
instance_id,
dbid,
authentication_type,
userid,
proxy_userid,
external_userid,
global_userid,
client_program_name,
dblink_info,
xs_user_name,
xs_sessionid,
entry_id,
statement_id,
CAST (event_timestamp AS TIMESTAMP WITH LOCAL TIME ZONE),
act.name,
return_code,
os_process,
transaction_id,
scn,
execution_id,
obj_owner,
obj_name,
sql_text,
sql_binds,
application_contexts,
client_identifier,
new_owner,
new_name,
object_edition,
system_privilege_used,
spx.name,
aom.name,
object_privileges,
role,
target_user,
excluded_user,
excluded_schema,
excluded_object,
additional_info,
unified_audit_policies,
fga_policy_name,
xs_inactivity_timeout,
xs_entity_type,
xs_target_principal_name,
xs_proxy_user_name,
xs_datasec_policy_name,
xs_schema_name,
xs_callback_event_type,
xs_package_name,
xs_procedure_name,
xs_enabled_role,
xs_cookie,
xs_ns_name,
xs_ns_attribute,
xs_ns_attribute_old_val,
xs_ns_attribute_new_val,
dv_action_code,
dv_action_name,
dv_extended_action_code,
dv_grantee,
dv_return_code,
dv_action_object_name,
dv_rule_set_name,
dv_comment,
dv_factor_context,
dv_object_status,
ols_policy_name,
ols_grantee,
ols_max_read_label,
ols_max_write_label,
ols_min_write_label,
ols_privileges_granted,
ols_program_unit_name,
ols_privileges_used,
ols_string_label,
ols_label_component_type,
ols_label_component_name,
ols_parent_group_name,
ols_old_value,
ols_new_value,
rman_session_recid,
rman_session_stamp,
rman_operation,
rman_object_type,
rman_device_type,
dp_text_parameters1,
dp_boolean_parameters1,
direct_path_num_columns_loaded
FROM gv$unified_audit_trail uview,
all_unified_audit_actions act,
system_privilege_map spx,
stmt_audit_option_map aom
WHERE uview.action = act.action(+)
AND -uview.system_privilege = spx.privilege(+)
AND uview.audit_option = aom.option#(+)
AND uview.audit_type = act.TYPE;)
  desc 'fix', %q(Configure the DBMS's auditing to audit standard and organization-defined auditable events, the audit record to include where the event occurred. If preferred, use a third-party or custom tool.

If using a third-party product, proceed in accordance with the product documentation. If using Oracle's capabilities, proceed as follows.

If Standard Auditing is used:
Use this process to ensure auditable events are captured:

ALTER SYSTEM SET AUDIT_TRAIL=<audit trail type> SCOPE=SPFILE;

Audit trail type can be 'OS', 'DB', 'DB,EXTENDED', 'XML' or 'XML,EXTENDED'.
After executing this statement, it may be necessary to shut down and restart the Oracle database.

If Unified Auditing is used:
To ensure auditable events are captured:
Link the oracle binary with uniaud_on, and then restart the database.                                                                                                                                                                                 
 Oracle Database Upgrade Guide describes how to enable unified auditing.

For more information on the configuration of auditing, refer to the following documents:
"Auditing Database Activity" in the Oracle Database 2 Day + Security Guide:
http://docs.oracle.com/database/121/TDPSG/tdpsg_auditing.htm#TDPSG50000
"Monitoring Database Activity with Auditing" in the Oracle Database Security Guide:
http://docs.oracle.com/database/121/DBSEG/part_6.htm#CCHEHCGI
"DBMS_AUDIT_MGMT" in the Oracle Database PL/SQL Packages and Types Reference:
http://docs.oracle.com/database/121/ARPLS/d_audit_mgmt.htm#ARPLS241
Oracle Database Upgrade Guide:
http://docs.oracle.com/database/121/UPGRD/afterup.htm#UPGRD52810)
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-21987r667274_chk'
  tag severity: 'medium'
  tag gid: 'V-220272'
  tag rid: 'SV-220272r666961_rule'
  tag stig_id: 'O121-C2-007600'
  tag gtitle: 'SRG-APP-000097-DB-000041'
  tag fix_id: 'F-21979r391948_fix'
  tag 'documentable'
  tag legacy: ['SV-76123', 'V-61633']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
