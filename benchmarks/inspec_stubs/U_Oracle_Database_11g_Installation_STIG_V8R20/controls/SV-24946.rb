control 'SV-24946' do
  title 'Oracle SQLNet and listener log files should not be accessible to unauthorized users.'
  desc 'The SQLNet and Listener log files provide audit data useful to the discovery of suspicious behavior. The log files may contain usernames and passwords in clear text as well as other information that could aid a malicious user with unauthorized access attempts to the database. Generation and protection of these files helps support security monitoring efforts.'
  desc 'check', 'Locate the Listener and SQLNet log files. View the contents of the sqlnet.ora and listener.ora configuration files located in the ORACLE_HOME/network/admin directory or the directory specified by the TNS_ADMIN environment variable (if set) for the listener process/service account:

If the sqlnet.ora parameter TRACE_LEVEL_SERVER is not defined or is set to OFF OR 0, SQLNet logging is not enabled and the check for these parameters below is Not a Finding, otherwise, verify the directories specified in the following parameters of the sqlnet.ora file exist:
  
LOG_FILE_SERVER = sqlnet [filename is sqlnet.log]
LOG_DIRECTORY_SERVER = [directory on a volume with enough free space]

Verify the directories and files specified in the following parameters of the listener.ora exist:

NOTE: If you are using Automatic Diagnostic Repository (ADR) logging (DIAG_ADR_ENABLED_[listener name] = ON in listener.ora), the following parameters are Not Applicable. Setting DIAG_ADR_ENABLED_[listener name] = OFF reverts to traditional listener tracing/logging and the following parameters are in effect. For more information on Automatic Diagnostic Repository (ADR), refer to Oracle MetaLink Note 454927.1.

LOG_DIRECTORY_[listener name] = [directory on a volume with enough free space]
LOG_FILE_[listener name] = listener
TRACE_DIRECTORY_[listener name] = [directory on a volume with enough free space]

Default log file locations (by Oracle Version):

  -  DIAG_ADR_ENABLED_[listener name] = OFF:

   -- listener log directory and file: ORACLE_HOME/network/log/listener.log
   -- listener trace directory and files: ORACLE_HOME/network/trace/listener.trc
   -- sqlnet log file: ORACLE_HOME/network/log/sqlnet.log 
   -- sqlnet trace file: ORACLE_HOME/network/trace/sqlnet.trc

  -  DIAG_ADR_ENABLED_[listener name] = ON:

NOTE: The ADR_HOME is defined from the ADR_BASE parameter. If ADR_BASE is not defined, then ADR_BASE is set to the value of the DIAGNOSTIC_DEST initialization parameter, or if DIAGNOSTIC_DEST is not defined, then the value of the ORACLE_BASE environment variable is used. See Oracle MetaLink Note 453125.1 for more information on ADR file locations.

   -- listener log directory and file: [ADR_HOME]/alert/log.xml  
   -- listener trace log directory and files: [ADR_HOME]/trace/alert_[SID].log and [ADR_HOME]/trace/*.trc  
   -- sqlnet log file: [ADR_BASE]/diag/clients/[database name]/[SID]/trace/sqlnet.log and [listener name].log
   -- sqlnet trace file: [ADR_BASE]/diag/clients/[database name]/[SID]/trace/*.trc

The listener log file location may also be determined using the lsnrctl utility, STATUS command, and viewing the value displayed for listener log file.

Review access permissions assigned to the files and directories:

  -  For UNIX, verify that the permissions on the directory and log files are restricted to the Oracle software owner and OS DBA and/or Listener process group.

  -  For Windows, verify that the file permissions on the listener.log and sqlnet.log files restrict access to the Oracle software owner and OS DBA and/or Listener process group.

If access to the files is not restricted as listed above, this is a Finding.'
  desc 'fix', 'Restrict access to the listener and sqlnet log files.

Restrict access to the tnslsnr service account to DBAs, SAs and auditors where they are required by assigned responsibilities.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-26572r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2612'
  tag rid: 'SV-24946r1_rule'
  tag stig_id: 'DO5037-ORACLE11'
  tag gtitle: 'Oracle SQLNet and listener log files protection'
  tag fix_id: 'F-26555r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
