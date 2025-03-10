control 'SV-224303' do
  title 'Sensitive CICS transactions are not protected in accordance with security requirements.'
  desc 'Sensitive CICS transactions offer the ability to circumvent transaction level controls for accessing resources under CICS. These transactions must be protected so that only authorized users can access them. Unauthorized use can result in the compromise of the confidentiality, integrity, and availability of the operating system or customer data.'
  desc 'check', 'a) Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(TRANS)
- ACF2CMDS.RPT(RESOURCE) - Alternate report

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b) Browse the data set allocated by the ACF2PARM DD statement in each CICS startup procedure. Determine the resource type for transactions. Example:

CICSKEY OPTION=VALIDATE,TYPE=resource type, RESOURCE=TRANS

c) Ensure the following items are in effect for all CICS transactions for each resource type:

NOTE:  Authorized personnel include systems programming and security staffs. Additional guidance regarding authorized personnel for specific transactions is included in this z/OS STIG Addendum. For example, CEMT SPI provides a broader use of this sensitive transaction by restricting execution to inquiries.

1) Transactions, listed in tables CICS CATEGORY 2 CICS AND OTHER PRODUCT TRANSACTIONS and CICS CATEGORY 4 COTS-SUPPLIED SENSITIVE TRANSACTIONS, in the z/OS STIG Addendum, are restricted to authorized personnel.

Note: The exception to this is the CEOT and CSGM transactions, which can be made available to all users.
Note: The exception to this is the CWBA transaction, can be made available to the CICS Default user.
Note: The transactions beginning with "CK" apply to regions running WebSphere MQ.
Note: Category 1 transactions are internally restricted to CICS region userids.
 
d) If (c) is true for all CICS regions, there is no finding.

e) If (c) is untrue for any CICS region, this is a finding.'
  desc 'fix', 'The ISSO will ensure that each CICS region is  associated with a unique userid and that userid is properly defined.

Develop a plan to implement the required changes.

1. Most transactions are protected in groups. An example would be "KT2" which would contain all Category 2 transactions. KT2 is defined to ACF2 as a resource and contains all the Category 2 transactions.

An example of how to implement this within ACF2 is shown here:

$KEY(CEMT) TYPE(KT2)          
  UID(syspaudt) ALLOW     
 UID(*) PREVENT              

2. Transactions groups should be defined and permitted in accordance with the CICS Transaction tables listed in the z/OS STIG Addendum.'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for ACF2'
  tag check_id: 'C-25980r868093_chk'
  tag severity: 'medium'
  tag gid: 'V-224303'
  tag rid: 'SV-224303r868095_rule'
  tag stig_id: 'ZCIC0020'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25968r868094_fix'
  tag 'documentable'
  tag legacy: ['SV-251', 'V-251']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
