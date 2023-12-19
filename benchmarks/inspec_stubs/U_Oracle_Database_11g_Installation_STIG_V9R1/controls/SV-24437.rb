control 'SV-24437' do
  title 'The DBMS requires a System Security Plan containing all required information.'
  desc 'A System Security Plan identifies security control applicability and configuration for the DBMS. It also contains security control documentation requirements. Security controls applicable to the DBMS may not be documented, tracked or followed if not identified in the System Security Plan. Any omission of security control consideration could lead to an exploit of DBMS vulnerabilities.'
  desc 'check', 'Review the System Security Plan for the DBMS.

Review coverage of the following in the System Security Plan:
-  Technical, administrative and procedural IA program and policies that govern the DBMS
-  Identification of all IA personnel (IAM, IAO, DBA, SA) assigned responsibility to the DBMS
-  Specific IA requirements and objectives (e.g., requirements for data handling or dissemination (to include identification of sensitive data stored in the database, database application user job functions/roles and privileges), system redundancy and backup, or emergency response)

If a System Security Plan does not exist or does not identify or reference all relevant security controls, this is a Finding.'
  desc 'fix', 'Develop, document and implement a System Security Plan for the DBMS.

Include IA documentation related to the DBMS in the System Security Plan for the system that the DBMS supports.

Review section 3.4 - System Security Plan Overview in the ORACLE DATABASE SECURITY CHECKLIST for more information.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-29375r1_chk'
  tag severity: 'low'
  tag gid: 'V-15150'
  tag rid: 'SV-24437r1_rule'
  tag stig_id: 'DG0154-ORACLE11'
  tag gtitle: 'DBMS System Security Plan'
  tag fix_id: 'F-26400r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
