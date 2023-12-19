control 'SV-55940' do
  title 'The Oracle SEC_PROTOCOL_ERROR_FURTHER_ACTION parameter should be set to a value of DELAY or DROP.'
  desc 'The database is vulnerable to exhaustion of resources that could result in a Denial of Service (DoS) to other clients if not protected from a flood of bad packets submitted by a malicious or errant client connection.  The sec_protocol_error_further_action initialization parameter can be set to delay or drop acceptance of bad packets from a client in order to support the continued function of other non-problematic connections.'
  desc 'check', "From SQL*Plus:

  select upper(value) from v$parameter
   where name = 'sec_protocol_error_further_action';

If the value returned does not include DROP or DELAY, this is a Finding."
  desc 'fix', "Set the value for the sec_protocol_error_further_action initialization parameter to DROP or DELAY.

DROP provides better protection and is recommended.

From SQL*Plus:

  alter system set sec_protocol_error_further_action = 'drop' scope = spfile;
    OR
  alter system set sec_protocol_error_further_action = 'drop,3' scope = spfile;

NOTE: The addition of the ‘,3’ above further limits the number of ‘bad packets’ to the specified number before forcefully terminating the connection.

The above SQL*Plus command will set the parameter to take effect at next system startup."
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-17062r2_chk'
  tag severity: 'medium'
  tag gid: 'V-16053'
  tag rid: 'SV-55940r2_rule'
  tag stig_id: 'DO6750-ORACLE11'
  tag gtitle: 'Oracle SEC_PROTOCOL_ERROR_FURTHER_ACTION parameter'
  tag fix_id: 'F-16156r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
