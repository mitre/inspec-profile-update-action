control 'SV-24429' do
  title 'Users should be alerted upon login of previous successful connections or unsuccessful attempts to access their account.'
  desc 'Unauthorized access to DBMS accounts may go undetected if account access is not monitored. Authorized users may serve as a reliable party to report unauthorized use of to their account.'
  desc 'check', 'If the database does not store or process classified data, or user accounts are prohibited from accessing the database interactively, this check is Not a Finding.  

NOTE: Per the STIG, The definition of an Interactive Database User can be considered an end-user who accesses the database interactively using tools like SQL*Plus, TOAD, etc. and not through a mid-tier application. Your DAA has the option to consider administration accounts (SYSDBA, SYSOPER, SCHEMA accounts and accounts assigned DBA privileges) as Interactive Database User accounts for the purposes of this check. The definition of an Interactive Database User should be documented in the System Security Plan.

Have the DBA perform an interactive logon test (via SQL*Plus) using a non-privileged account (and a privileged account if privileged accounts meet this requirement) to verify display of user access and account usage.

If the last successful and number of unsuccessful attempts since the last successful attempt are not reported, this is a Finding.'
  desc 'fix', 'Develop, document and implement an automated method to display at interactive logon the time and date of the last successful login and the number of failed login attempts since the last successful login for users that access the database interactively.

This may require a custom-developed logon trigger or procedure to accomplish.

NOTE: This may cause interaction/functionality problems with COTS applications not designed for this kind of interaction.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29367r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15641'
  tag rid: 'SV-24429r1_rule'
  tag stig_id: 'DG0135-ORACLE11'
  tag gtitle: 'DBMS connection alert'
  tag fix_id: 'F-26391r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
