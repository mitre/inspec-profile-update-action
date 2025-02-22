control 'SV-28568' do
  title 'Custom and GOTS application source code stored in the database should be protected with encryption or encoding.'
  desc 'Source code may include information on data relationships, locations of sensitive data that are otherwise obscured, or other processing information that could aid a malicious user. Encoding or encryption of the custom source code objects within the database helps protect against this type of disclosure.'
  desc 'check', "If this is not a production database, this check is Not a Finding.

From SQL*Plus (NOTE: The owner list below is a short list of all possible default Oracle accounts):
  select owner||'.'||name from dba_source
  where line=1 and owner not in
  ('SYS', 'CTXSYS', 'MDSYS', 'ODM', 'OE', 'OLAPSYS', 'ORDPLUGINS',
   'ORDSYS', 'OUTLN', 'PM', 'QS_ADM', 'RMAN', 'SYSTEM', 'WKSYS',
   'WMSYS', 'XDB')
  and owner not like 'OEM%'
  and text not like '%wrapped%'
  and type in ('PROCEDURE', 'FUNCTION', 'PACKAGE BODY');

Review the list of results with the DBA. If any results are custom or GOTS application code, this is a Finding. If all returned results are default DBMS or COTS application code, this is not a Finding."
  desc 'fix', "Use the Oracle WRAP utility to encode application source code stored in application database objects (stored procedures, functions, package bodies).

The following may be used as an example process:

1)  export the application object source and store in an external file.

From SQL*Plus:
  set show off
  set heading off
  set verify off
  set echo off
  set term off
  set pagesize 0
  set feedback off
  set serveroutput on size 1000000
  set wrap on
  set trimspool on
  set linesize 512
  spool [output file name = proc.sql]
  select text from dba_source
  where object_name='[object name]';
  spool off

2)  From system command line, invoke the wrap utility.

  wrap iname=proc.sql oname=proc.plb

This will result in the file name proc.plb

3)  re-create the object with the encoded source code.

From SQL*Plus:
  @proc.plb"
  impact 0.3
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-28830r2_chk'
  tag severity: 'low'
  tag gid: 'V-3823'
  tag rid: 'SV-28568r2_rule'
  tag stig_id: 'DG0091-ORACLE11'
  tag gtitle: 'DBMS source code encoding or encryption'
  tag fix_id: 'F-25838r1_fix'
  tag responsibility: 'Database Administrator'
end
