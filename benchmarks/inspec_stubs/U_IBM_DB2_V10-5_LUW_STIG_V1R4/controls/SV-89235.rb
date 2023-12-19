control 'SV-89235' do
  title 'When supporting applications that require security labeling of data, DB2 must associate organization-defined types of security labels having organization-defined security label values with information in storage.'
  desc 'Without the association of security labels to information, there is no basis for the DBMS to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. 

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy. 

One example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

The mechanism used to support security labeling may be a feature of the DBMS product, a third-party product, or custom application code.'
  desc 'check', 'If security labeling is not required, this is not a finding.

Query the system catalog to find out the existing security labels:
DB2> SELECT * FROM SYSCAT.SECURITYLABELS

If the required labels are not created in database this is a finding.

Query the following catalog views find details of existing security labels:
DB2> SELECT * FROM SYSCAT.SECURITYLABELACCESS
DB2> SELECT * FROM SYSCAT.SECURITYLABELCOMPONENTELEMENTS
DB2> SELECT * FROM SYSCAT.SECURITYLABELCOMPONENTS

If the security labels are not defined as per organization security policies, this is a finding.'
  desc 'fix', "Use Create security Label statement to create the security labels: 

See the following example to create the components, policy and then security labels:

Create the components for Security labels:
DB2> CREATE SECURITY LABEL COMPONENT LEVEL ARRAY ['Top Secret', 'Secret', 'Confidential', 'Unclassified'];
DB2> CREATE SECURITY LABEL COMPONENT COMPARTMENTS SET {'Collection', 'Research', 'Analysis'};

Create the Policy:
DB2> CREATE SECURITY POLICY DATA_ACCESS COMPONENTS LEVEL, COMPARTMENTS WITH DB2LBACRULES;

Create Security Label:
DB2> CREATE SECURITY LABEL DATA_ACCESS.EMPLOYEESECLABEL COMPONENT LEVEL 'Top Secret', COMPONENT COMPARTMENTS 'Research', 'Analysis'

After creating the security labels, use one of the following statements to attach the labels to the table:
DB2>  CREATE TABLE
  Or
DB2> ALTER TABLE

For advice and examples, see the tutorial at:
https://www.ibm.com/developerworks/data/tutorials/dm0605wong/
https://www.ibm.com/developerworks/data/tutorials/dm0605wong/section2.html

Note: Select the following knowledgebase link for information regarding LBAC Details: 
http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.admin.sec.doc/doc/c0021114.html

Select the following knowledgebase link for information regarding Create Security Label: 
http://www.ibm.com/support/knowledgecenter/SSEPGG_10.5.0/com.ibm.db2.luw.sql.ref.doc/doc/r0020026.html?cp=SSEPGG_10.5.0%2F2-12-7-94"
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74447r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74561'
  tag rid: 'SV-89235r1_rule'
  tag stig_id: 'DB2X-00-006600'
  tag gtitle: 'SRG-APP-000311-DB-000308'
  tag fix_id: 'F-81161r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002262']
  tag nist: ['AC-16 a']
end
