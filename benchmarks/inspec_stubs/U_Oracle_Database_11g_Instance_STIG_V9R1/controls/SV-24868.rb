control 'SV-24868' do
  title 'The Oracle SID should not be the default SID.'
  desc 'Use of the default Oracle System Identifier (SID) leaves the database vulnerable to attacks that target Oracle installations running under default SID. Using a custom name helps protect the database against this kind of targeted attack.'
  desc 'check', 'From SQL*Plus:

  select instance_name from v$instance;

Review the instance name with the DBA.

Ask the DBA if the instance name was chosen by the installer to conform to local naming conventions, etc. or if it was determined by the installation software.

If it was named by the installation software, this is a Finding.'
  desc 'fix', 'Follow the instructions in Oracle MetaLink Note 15390.1 (and related documents) to change the SID for the database without re-creating the database to a value other than the application default.'
  impact 0.3
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-29424r2_chk'
  tag severity: 'low'
  tag gid: 'V-3848'
  tag rid: 'SV-24868r2_rule'
  tag stig_id: 'DO0221-ORACLE11'
  tag gtitle: 'Oracle default SID name'
  tag fix_id: 'F-26451r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
