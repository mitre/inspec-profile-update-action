control 'SV-24379' do
  title 'Use of the DBMS software installation account should be restricted to DBMS software installation, upgrade and maintenance actions.'
  desc 'The DBMS software installation account is granted privileges not required for DBA or other functions. Use of accounts configured with excess privileges may result in unauthorized or unintentional compromise of the DBMS.'
  desc 'check', 'Review the DBMS account usage log for use of the Oracle DBMS software installation account.

Interview personnel authorized to access the DBMS software installation account to ask how the account is used.

If any usage of the account is to support daily operations or general DBA responsibilities, this is a Finding.
 
NOTE: On Windows systems, the Oracle DBMS software is installed using an account with administrator privileges. Ownership should be reassigned to a dedicated OS account used to operate the DBMS software. Except where a change in ownership is made to files/directories during a software update, any check results are not a Finding.'
  desc 'fix', 'Develop, document, implement procedures, and train authorized users to restrict usage of the DBMS software installation account for DBMS software installation, upgrade and maintenance only where applicable.

For Windows systems, reapplication of the fix for Check DG0019 may be necessary to reestablish correct file/directory ownership.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29145r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15111'
  tag rid: 'SV-24379r1_rule'
  tag stig_id: 'DG0042-ORACLE11'
  tag gtitle: 'DBMS software installation account use'
  tag fix_id: 'F-26154r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
