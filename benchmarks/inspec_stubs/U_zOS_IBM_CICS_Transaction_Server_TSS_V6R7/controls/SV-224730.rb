control 'SV-224730' do
  title 'Sensitive CICS transactions are not protected in accordance with security requirements.'
  desc 'Sensitive CICS transactions offer the ability to circumvent transaction level controls for accessing resources under CICS.  These transactions must be protected so that only authorized users can access them.  Unauthorized use can result in the compromise of the confidentiality, integrity, and availability of the operating system or customer data.'
  desc 'check', 'a)	Refer to the following reports produced by the TSS Data Collection and Data Set and Resource Data Collection:

-	TSSCMDS.RPT(WHOOOTRA)
-	SENSITVE.RPT(WHOHOTRA)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b)	Ensure the following items are in effect for all CICS regions:

NOTE:	Authorized personnel include systems programming and security staffs.  Additional guidance regarding authorized personnel for specific transactions is included in this z/OS STIG Addendum.  For example, CEMT SPI provides a broader use of this sensitive transaction by restricting execution to inquiries.

1)	Transactions listed in tables CICS CATEGORY 2 CICS AND OTHER PRODUCT TRANSACTIONS and CICS CATEGORY 4 COTS-SUPPLIED SENSITIVE TRANSACTIONS, in the z/OS STIG Addendum, are restricted to authorized personnel.

Note:	The exception to this is the CEOT and CSGM transactions, which can be made available to all users.
Note:	The exception to this is the CWBA transaction, can be made available to the CICS Default user.
Note:	The transactions beginning with "CK" apply to regions running WebSphere MQ.
Note:	Category 1 transactions are internally restricted to CICS region userids.

c)	If sensitive transactions referenced in (b) are protected as indicated, there is NO FINDING.

d)	If any sensitive transaction referenced in (b) is not protected as indicated, this is a FINDING.'
  desc 'fix', %q(Develop a plan to implement the required changes.

1. Most transactions are protected by profiles. An example would be "L2TRANS" which would be permitted all Category 2 transactions. L2TRANS is defined to CA-TSS as a profile and is permitted to all the Category 2 transactions. An example of how to implement this within CA-TSS is shown here:

TSS CRE(L2TRANS) TYPE(PROF) DEPT(<dept acid>) NAME('L2 TRANS')  INSTDATA('PROFILE GRANTING ACCESS TO ALL CATEGORY 2 TRANS')    

TSS ADD(<owning acid>) OTRAN(CADP CBAM CDBC)

TSS PER(L2TRANS) OTRAN(CADP CBAM CDBC)

Permission to the transaction group can be accomplished with a sample command:

TSS PER(USERID)OTRAN(TRANSACTION)

Permission to the transactions can be accomplished by adding the L2TRANS profile to a user's ACID.

Example:

TSS ADD(<user's acid>) PROF(L2TRANS)

2. Transactions groups should be defined and permitted in accordance with the CICS Transaction tables listed in the zOS STIG Addendum.)
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for TSS'
  tag check_id: 'C-26421r520292_chk'
  tag severity: 'medium'
  tag gid: 'V-224730'
  tag rid: 'SV-224730r520294_rule'
  tag stig_id: 'ZCIC0020'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26409r520293_fix'
  tag 'documentable'
  tag legacy: ['SV-7529', 'V-251']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
