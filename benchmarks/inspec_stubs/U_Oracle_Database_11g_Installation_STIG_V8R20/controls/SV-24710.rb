control 'SV-24710' do
  title 'Sensitive data is stored in the database and should be identified in the System Security Plan and AIS Functional Architecture documentation.'
  desc 'A DBMS that does not have the correct confidentiality level identified or any confidentiality level assigned is not being secured at a level appropriate to the risk it poses.'
  desc 'check', 'If no sensitive or classified data is stored in the database, listed in the System Security Plan and listed in the AIS Functional Architecture documentation, this check is Not a Finding.

Review AIS Functional Architecture documentation for the DBMS and note any sensitive data that is identified.

Review database table column data or descriptions that indicate sensitive data.

For example, a data column labeled "SSN" could indicate social security numbers are stored in the column.

Question the IAO or DBA where any questions arise.

General categories of sensitive data requiring identification include any personal data (health, financial, social security number and date of birth), proprietary or financially sensitive business data or data that might be classified.

If any data is considered sensitive and is not documented in the AISFA, this is a Finding.'
  desc 'fix', 'Include identification of any sensitive data in the AIS Functional Architecture and the System Security Plan.

Include data that appear to be sensitive with a discussion as to why it is not marked as such.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29345r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15144'
  tag rid: 'SV-24710r1_rule'
  tag stig_id: 'DG0107-ORACLE11'
  tag gtitle: 'DBMS sensitive data identification'
  tag fix_id: 'F-26370r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
