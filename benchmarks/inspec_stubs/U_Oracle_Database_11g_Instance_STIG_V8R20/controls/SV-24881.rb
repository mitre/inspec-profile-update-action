control 'SV-24881' do
  title 'The Oracle OS_ROLES parameter should be set to FALSE.'
  desc 'The OS_ROLES parameter specifies whether Oracle roles are defined and managed by the DBMS or by the host operating system. To maintain and support the separation of duties between host system administration and DBMS administration, the DBMS must be configured to use only roles defined and managed by the DBA. Separation of duties supports assignment of privileges by job function and supports accountability.'
  desc 'check', "From SQL*Plus:

  select value from v$parameter where name = 'os_roles';

If the value returned is not FALSE, this is a Finding."
  desc 'fix', 'From SQL*Plus:

  alter system set os_roles = FALSE scope = spfile;

The above SQL*Plus command will set the parameter to take effect at next system startup.'
  impact 0.3
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29433r2_chk'
  tag severity: 'low'
  tag gid: 'V-2519'
  tag rid: 'SV-24881r2_rule'
  tag stig_id: 'DO0240-ORACLE11'
  tag gtitle: 'Oracle OS_ROLES parameter'
  tag fix_id: 'F-26462r1_fix'
  tag 'documentable'
  tag responsibility: ['Database Administrator', 'Information Assurance Officer']
end
