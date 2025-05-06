control 'SV-224650' do
  title 'CL/SuperSession is not properly configured to generate SMF records for audit trail and accounting reports.'
  desc 'Product configuration/parameters control the security and operational characteristics of products.  If these parameter values are improperly specified, security and operational controls may be weakened.  This exposure may threaten the availability of the product applications, and compromise the confidentiality of customer data.'
  desc 'check', 'a)	Review the member KLVINNAF in the TLVPARM DD statement concatenation of the CL/Supersession STC procedure.  (This member is located in SYS3.OMEGAMON.qualifier.RLSPARM.)

Refer to the following report produced by the z/OS Data Collection:

-	EXAM.RPT(SMFOPTS)

Automated Analysis
Refer to the following report produced by the z/OS Data Collection:

-	PDI(ZCLS0041)

b)	If the SMF= field specifies an SMF record number, review the SMFOPTS report to verify SMF is writing that record type.

c)	If SMF is writing the record number specified by SMF=, there is NO FINDING.

d)	If the SMF= field does not specify an SMF record number, or SMF is not writing the record number specified by SMF=, this is a FINDING.'
  desc 'fix', 'The Systems Programmer and IAO will review all session manager security parameters and control options for compliance. To ensure that the Session Manager generates SMF records for audit trail and accounting reports.

To provide an audit trail of user activity in CL/SuperSession, configure the Network Accounting Facility (NAF) to require SMF recording of accounting and audit data.  Accounting to the journal data set is optional at the discretion of the site.  To accomplish this, configure the following NAF startup parameters in the KLVINNAF member of the RLSPARM initialization parameter library as follows:

DSNAME= dsname	Name of the NAF journal data set.  Required only if the site is collecting accounting and audit data in the journal data set in addition to the SMF data.

MOD	If the journal data set is used, this parameter should be set to ensure that logging data in the data set is not overwritten.

SMF=nnn	SMF record number.  This field is mandatory to ensure that CL/SuperSession data is always written to the SMF files.'
  impact 0.5
  ref 'DPMS Target zOS CLSuperSession for TSS'
  tag check_id: 'C-26333r519767_chk'
  tag severity: 'medium'
  tag gid: 'V-224650'
  tag rid: 'SV-224650r519769_rule'
  tag stig_id: 'ZCLS0041'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26321r519768_fix'
  tag 'documentable'
  tag legacy: ['V-22689', 'SV-27198']
  tag cci: ['CCI-000035']
  tag nist: ['AC-4 (11)']
end
