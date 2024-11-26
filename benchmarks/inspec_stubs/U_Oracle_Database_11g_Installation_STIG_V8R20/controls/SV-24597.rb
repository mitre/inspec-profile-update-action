control 'SV-24597' do
  title 'Database executable and configuration files should be monitored for unauthorized modifications.'
  desc 'Changes to files in the DBMS software directory including executable, configuration, script, or batch files can indicate malicious compromise of the software files. Changes to non-executable files, such as log files and data files, do not usually reflect unauthorized changes, but are modified by the DBMS as part of normal operation. These modifications can be ignored.'
  desc 'check', 'Ask the DBA to describe/demonstrate any software modification detection procedures in place and request documents of these procedures for review.

Verify by reviewing reports for inclusion of the DBMS executable and configuration files.

If documented procedures and proof of implementation does not exist that includes review of the database software directories and database application directories, this is a Finding.'
  desc 'fix', 'Develop, document and implement procedures to monitor changes made to the DBMS software.

Identify all database files and directories to be included in the host system or database backups and provide these to the person responsible for backups.

For Windows systems, you can use the dir /s > filename.txt run weekly to store and compare file modification/creation dates and file sizes using the DOS fc command.

For UNIX systems, you can use the ls –as >filename.txt command to store and compare (diff command) file statistics for comparison.

These are not as comprehensive as some tools available, but may be enhanced by including checks for checksums or file hashes.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-17065r1_chk'
  tag severity: 'low'
  tag gid: 'V-2420'
  tag rid: 'SV-24597r1_rule'
  tag stig_id: 'DG0010-ORACLE11'
  tag gtitle: 'DBMS software monitoring'
  tag fix_id: 'F-3428r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
