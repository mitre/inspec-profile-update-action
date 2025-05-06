control 'SV-224493' do
  title 'Sensitive CICS transactions are not protected in accordance with security requirements.'
  desc 'Sensitive CICS transactions offer the ability to circumvent transaction level controls for accessing resources under CICS.  These transactions must be protected so that only authorized users can access them.  Unauthorized use can result in the compromise of the confidentiality, integrity, and availability of the operating system or customer data.'
  desc 'check', 'a)	Refer to the following reports produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(TCICSTRN)
-	SENSITVE.RPT(GCICSTRN)

NOTE:	If a CICS region is using a site-defined transaction resource class pair, execute a RACF RLIST command against these resource classes.

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b)	Ensure the following items are in effect for all CICS regions:

1)	Transactions listed in tables CICS CATEGORY 2 CICS AND OTHER PRODUCT TRANSACTIONS and CICS CATEGORY 4 COTS-SUPPLIED SENSITIVE TRANSACTIONS, in the z/OS STIG Addendum, are restricted to authorized personnel.

Note:	The exception to this is the CEOT and CSGM transactions, which can be made available to all users.
Note:	The exception to this is the CWBA transaction, can be made available to the CICS Default user.
Note:	The transactions beginning with "CK" apply to regions running WebSphere MQ.
Note:	Category 1 transactions are internally restricted to CICS region userids.

c)	If the items mentioned in (b) are true for all CICS transaction resource classes, there is NO FINDING.

d)	If any item mentioned in (b) is untrue for a CICS transaction resource class, this is a FINDING.'
  desc 'fix', 'Develop a plan to implement the required changes.

1. Most transactions are protected in groups. An example would be "L2TRANS" which would contain all Category 2 transactions. L2TRANS is defined to RACF as a profile and contains all the Category 2 transactions. An example of how to implement this within RACF is shown here:

RDEF GCICSTRN L2TRANS UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ))

RALT GCICSTRN L2TRANS ADDMEM(CADP CBAM CDBC)

Permission to the transaction group can be accomplished with a sample command:

PE L2TRANS CL(GCICSTRN) id(<syspaudt>)

Note that a refresh is generally needed to the member class.
In this case TCICSTRN is the member class for GCICSTRN and a sample refresh command is

SETR RACL(TCICSTRN) REFRESH

2. Transactions groups should be defined and permitted in accordance with the CICS Transaction
tables listed in the zOS STIG Addendum.'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for RACF'
  tag check_id: 'C-26176r520265_chk'
  tag severity: 'medium'
  tag gid: 'V-224493'
  tag rid: 'SV-224493r520267_rule'
  tag stig_id: 'ZCIC0020'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26164r520266_fix'
  tag 'documentable'
  tag legacy: ['SV-7528', 'V-251']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
