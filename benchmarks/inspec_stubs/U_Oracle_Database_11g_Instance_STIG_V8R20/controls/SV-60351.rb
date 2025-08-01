control 'SV-60351' do
  title 'Case sensitivity for passwords should be enabled.'
  desc 'Enablement of password case sensitivity allows Oracle password complexity to meet DoD password requirements. Password complexity decreases the likelihood of successful password attacks by malicious users.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'sec_case_sensitive_logon';

If the value returned is not TRUE, this is a Finding."
  desc 'fix', 'Enable case sensitive passwords.

From SQL*Plus:

  alter system set sec_case_sensitive_logon = TRUE scope = both;

The above SQL*Plus command will set the parameter to take effect immediately and permanently at next system startup.

NOTE:  Password and account requirements have changed for DoD since the STIG requirement listed in the table for this check was published.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-16814r2_chk'
  tag severity: 'medium'
  tag gid: 'V-16033'
  tag rid: 'SV-60351r1_rule'
  tag stig_id: 'DO6748-ORACLE11'
  tag gtitle: 'Oracle SEC_CASE_SENSITIVE_LOGON parameter'
  tag fix_id: 'F-16077r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
