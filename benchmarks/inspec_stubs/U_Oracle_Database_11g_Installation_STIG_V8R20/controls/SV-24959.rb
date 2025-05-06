control 'SV-24959' do
  title 'The Oracle SEC_PROTOCOL_ERROR_TRACE_ACTION parameter should not be set to NONE.'
  desc 'Undetected attacks using bad packets can lead to a successful Denial of Service (DoS) to database clients. Notification of attacks based on a flood of bad packets sent to the database can assist in discovery and response to this type of attack.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'sec_protocol_error_trace_action';

If the value returned is NONE, this is a Finding.

If the value returned is TRACE, LOG or ALERT, this is Not a Finding."
  desc 'fix', "Set the value for the sec_protocol_error_trace_action initialization parameter to ALERT or LOG.

TRACE may be appropriate for testing or development, but provides more detail than may be useful.

Consider using ALERT for MAC 1 systems.

From SQL*Plus:

  alter system set sec_protocol_error_trace_action = 'ALERT' scope = spfile;
    OR
  alter system set sec_protocol_error_trace_action = 'LOG' scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup."
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-26576r3_chk'
  tag severity: 'medium'
  tag gid: 'V-16054'
  tag rid: 'SV-24959r2_rule'
  tag stig_id: 'DO6752-ORACLE11'
  tag gtitle: 'Oracle SEC_PROTOCOL_ERROR_TRACE_ACTION parameter'
  tag fix_id: 'F-22866r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
