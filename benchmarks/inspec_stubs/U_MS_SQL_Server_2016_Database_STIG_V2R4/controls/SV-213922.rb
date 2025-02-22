control 'SV-213922' do
  title 'Execution of stored procedures and functions that utilize execute as must be restricted to necessary cases only.'
  desc 'In certain situations, to provide required functionality, a DBMS needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

Privilege elevation must be utilized only where necessary and protected from misuse.'
  desc 'check', "Review the system documentation to obtain a listing of stored procedures and functions that utilize impersonation. Execute the following query:


SELECT S.name AS schema_name, O.name AS module_name,
USER_NAME(
CASE M.execute_as_principal_id
WHEN -2 THEN COALESCE(O.principal_id, S.principal_id)
ELSE M.execute_as_principal_id
END
) AS execute_as
FROM sys.sql_modules M
JOIN sys.objects O ON M.object_id = O.object_id
JOIN sys.schemas S ON O.schema_id = S.schema_id
WHERE execute_as_principal_id IS NOT NULL
and       o.name not in 
(             
'fn_sysdac_get_username',
                             'fn_sysutility_ucp_get_instance_is_mi',
                             'sp_send_dbmail',
                             'sp_SendMailMessage',
                             'sp_syscollector_create_collection_set',
                             'sp_syscollector_delete_collection_set',
                             'sp_syscollector_disable_collector',
                             'sp_syscollector_enable_collector',
                             'sp_syscollector_get_collection_set_execution_status',
                             'sp_syscollector_run_collection_set',
                             'sp_syscollector_start_collection_set',
                             'sp_syscollector_update_collection_set',
                             'sp_syscollector_upload_collection_set',
                             'sp_syscollector_verify_collector_state',
                             'sp_syspolicy_add_policy',
                             'sp_syspolicy_add_policy_category_subscription',
                             'sp_syspolicy_delete_policy',
                             'sp_syspolicy_delete_policy_category_subscription',
                             'sp_syspolicy_update_policy',
                             'sp_sysutility_mi_add_ucp_registration',
                             'sp_sysutility_mi_disable_collection',
                             'sp_sysutility_mi_enroll',
                             'sp_sysutility_mi_initialize_collection',
                             'sp_sysutility_mi_remove',
                             'sp_sysutility_mi_remove_ucp_registration',
                             'sp_sysutility_mi_upload',
                             'sp_sysutility_mi_validate_enrollment_preconditions',
                             'sp_sysutility_ucp_add_mi',
                             'sp_sysutility_ucp_add_policy',
                             'sp_sysutility_ucp_calculate_aggregated_dac_health',
                             'sp_sysutility_ucp_calculate_aggregated_mi_health',
                             'sp_sysutility_ucp_calculate_computer_health',
                             'sp_sysutility_ucp_calculate_dac_file_space_health',
                             'sp_sysutility_ucp_calculate_dac_health',
                            'sp_sysutility_ucp_calculate_filegroups_with_policy_violations',
                             'sp_sysutility_ucp_calculate_health',
                             'sp_sysutility_ucp_calculate_mi_file_space_health',
                             'sp_sysutility_ucp_calculate_mi_health',
                             'sp_sysutility_ucp_configure_policies',
                             'sp_sysutility_ucp_create',
                             'sp_sysutility_ucp_delete_policy',
                             'sp_sysutility_ucp_delete_policy_history',
                             'sp_sysutility_ucp_get_policy_violations',
                             'sp_sysutility_ucp_initialize',
                             'sp_sysutility_ucp_initialize_mdw',
                             'sp_sysutility_ucp_remove_mi',
                             'sp_sysutility_ucp_update_policy',
                             'sp_sysutility_ucp_update_utility_configuration',
                             'sp_sysutility_ucp_validate_prerequisites',
                             'sp_validate_user',
                             'syscollector_collection_set_is_running_update_trigger',
                             'sysmail_help_status_sp'
)

ORDER BY schema_name, module_name

If any procedures or functions are returned that are not documented, this is a finding."
  desc 'fix', 'Alter stored procedures and functions to remove the "EXECUTE AS" statement.'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15140r313198_chk'
  tag severity: 'medium'
  tag gid: 'V-213922'
  tag rid: 'SV-213922r508025_rule'
  tag stig_id: 'SQL6-D0-002900'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag fix_id: 'F-15138r313199_fix'
  tag 'documentable'
  tag legacy: ['SV-93813', 'V-79107']
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
