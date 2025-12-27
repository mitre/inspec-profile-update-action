control 'SV-24564' do
  title 'The IDLE_TIME profile parameter should be set for Oracle profiles IAW DoD policy.'
  desc 'The Idle Time Resource Usage setting limits the maximum idle time allowed in a session. Idle time is a continuous inactive period during a session, expressed in minutes. Long-running queries and other operations are not subject to this limit. Setting an Idle Time Resource Usage limit helps prevent users from leaving applications open when they are away from their desks.'
  desc 'check', 'From SQL*Plus:

  select profile, limit from DBA_PROFILES
  where profile = ’DEFAULT’
  and resource_name = ’IDLE_TIME’;
  
  select profile, limit from DBA_PROFILES
  where profile <> ’DEFAULT’
  and resource_name = ’IDLE_TIME’;

If the idle time on the DEFAULT profile is greater than 15 minutes, this is a Finding.

If any non-default profiles have an idle time setting greater than 60 minutes or are set to an UNLIMITED value and not documented in the System Security Plan or not authorized by the IAO, this is a Finding.'
  desc 'fix', 'Modify profiles to meet the idle time requirement.

From SQL*Plus:

  alter profile default limit idle_time 15;
  alter profile [profile name] limit idle_time [IAO-approved value];

Authorize and document any profiles that require idle times greater than 15 minutes in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29465r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2552'
  tag rid: 'SV-24564r2_rule'
  tag stig_id: 'DO3536-ORACLE11'
  tag gtitle: 'Oracle IDLE_TIME profile parameter'
  tag fix_id: 'F-26529r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
