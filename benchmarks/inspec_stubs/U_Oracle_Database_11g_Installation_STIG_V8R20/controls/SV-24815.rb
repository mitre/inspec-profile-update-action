control 'SV-24815' do
  title 'An automated tool that monitors audit data and immediately reports suspicious activity should be employed for the DBMS.'
  desc 'Audit logs only capture information on suspicious events. Without an automated monitoring and alerting tool, malicious activity may go undetected and without response until compromise of the database or data is severe.'
  desc 'check', 'Review evidence or operation of an automated, continuous on-line monitoring and audit trail creation capability for the DBMS is deployed with the capability to immediately alert personnel of any unusual or inappropriate activity with potential IA implications, and with a user-configurable capability to automatically disable the system if serious IA violations are detected.

If the requirements listed above are not fully met, this is a Finding.'
  desc 'fix', 'Develop or procure, document and implement an automated, continuous on-line monitoring and audit trail creation capability for the DBMS is deployed with the capability to immediately alert personnel of any unusual or inappropriate activity with potential IA implications, and with a user-configurable capability to automatically disable the system if serious IA violations are detected.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29379r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15103'
  tag rid: 'SV-24815r1_rule'
  tag stig_id: 'DG0161-ORACLE11'
  tag gtitle: 'DBMS Audit Tool'
  tag fix_id: 'F-26404r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
