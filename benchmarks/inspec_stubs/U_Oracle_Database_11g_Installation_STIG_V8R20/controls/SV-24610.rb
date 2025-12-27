control 'SV-24610' do
  title 'A baseline of database application software should be documented and maintained.'
  desc 'Without maintenance of a baseline of current DBMS application software, monitoring for changes cannot be complete and unauthorized changes to the software can go undetected. Changes to the DBMS executables could be the result of intentional or unintentional actions.'
  desc 'check', 'Review DBMS software baseline procedures and implementation evidence.

Review the list of files, directories and details included in the current baseline for completeness.
  
If DBMS software configuration baseline procedures do not exist, evidence of implementation does not exist, or baseline is not documented and current, this is a Finding.'
  desc 'fix', 'Develop, document and implement DBMS software baseline procedures that include all DBMS software files and directories under the ORACLE_BASE and ORACLE_HOME environment variables and any custom and platform-specific directories.

Generate a list of files, directories and details for the DBMS software configuration baseline.

Update the configuration baseline after new installations, upgrades/updates or maintenance activities that include changes to the baseline software.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29111r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3806'
  tag rid: 'SV-24610r1_rule'
  tag stig_id: 'DG0021-ORACLE11'
  tag gtitle: 'DBMS software and configuration baseline'
  tag fix_id: 'F-26114r1_fix'
  tag 'documentable'
  tag responsibility: ['Database Administrator', 'Information Assurance Officer']
end
