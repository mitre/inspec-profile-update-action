control 'SV-24865' do
  title 'Oracle instance names should not contain Oracle version numbers.'
  desc 'Service names may be discovered by unauthenticated users. If the service name includes version numbers or other database product information, a malicious user may use that information to develop a targeted attack.'
  desc 'check', 'From SQL*Plus:

  select instance_name from v$instance;
  select version from v$instance;

If the instance name returned references the Oracle release number, this is a Finding.

Numbers used that include version numbers by coincidence are not a Finding.

The DBA should be able to relate the significance of the presence of a digit in the SID.'
  desc 'fix', 'Follow the instructions in Oracle MetaLink Note 15390.1 (and related documents) to change the SID for the database without re-creating the database to a value that does not identify the Oracle version.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29422r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2517'
  tag rid: 'SV-24865r1_rule'
  tag stig_id: 'DO0220-ORACLE11'
  tag gtitle: 'Oracle instance names'
  tag fix_id: 'F-26449r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
