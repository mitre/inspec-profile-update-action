control 'SV-24350' do
  title 'Database software directories including DBMS configuration files are stored in dedicated directories separate from the host OS and other applications.'
  desc 'Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directoriies both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application’s database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications.'
  desc 'check', 'For UNIX Systems:
  ls $ORACLE_BASE
  ls $ORACLE_HOME

If the ORACLE_BASE directory contains subdirectories other than ORACLE_HOME directories, a flash_recovery_area directory and an admin directory, verify they are used by the DBMS.

If they are not part of the Oracle DBMS software product, this is a Finding.

NOTE: Oracle DBMS data file storage may be placed on a separate, dedicated disk partition and linked to ORACLE_BASE. Refer to check DG0112.

For Windows Systems:
  echo %ORACLE_BASE%
  echo %ORACLE_HOME%

ORACLE_BASE, if defined, is usually set to C:\\Program Files\\Oracle.

If ORACLE_HOME is not in a dedicated directory separate from the OS software and other applications where supported by the DBMS, this is a Finding.

All Systems:
  Recommend dedicating a separate partition for the DBMS software libraries where supported by the DBMS on all platforms.'
  desc 'fix', 'Install Oracle DBMS software using directories separate from the OS and other application software library directories.

Re-locate any directories or re-install other application software that currently shares the DBMS software library directory to separate directories.

Recommend dedicating a separate partition for the DBMS software libraries where supported by the DBMS.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-19568r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4754'
  tag rid: 'SV-24350r1_rule'
  tag stig_id: 'DG0012-ORACLE11'
  tag gtitle: 'DBMS software storage location'
  tag fix_id: 'F-3797r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
