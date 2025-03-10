control 'SV-224310' do
  title 'CICS startup JCL statement is not specified in accordance with the proper security requirements.'
  desc 'The CICS SIT is used to define system operation and configuration parameters of a CICS system.  Several of these parameters control the security within a CICS region.  Failure to code the appropriate values could result in unexpected operations and degraded security.  This exposure may result in unauthorized access impacting the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the z/OS Data Collection:

	-	EXAM.RPT(CICSPROC)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b)	Ensure every CICS region on the system has the ACF2PARM DD statement in the CICS startup JCL.

c)	If the item in (b) is true for each CICS region, there is NO FINDING.

d)	If the item in (b) is untrue for a CICS region, this is a FINDING.'
  desc 'fix', 'The IAO will ensure that each CICS region procedure has the ACF2/CICS parameter dataset specified.

Ensure every CICS region on the system has the ACF2PARM DD statement in the CICS startup JCL.

View the started task proc for each CICS region in SYS3.PROCLIB using ISPF.'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for ACF2'
  tag check_id: 'C-25987r520250_chk'
  tag severity: 'medium'
  tag gid: 'V-224310'
  tag rid: 'SV-224310r520252_rule'
  tag stig_id: 'ZCICA022'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-25975r520251_fix'
  tag 'documentable'
  tag legacy: ['SV-7188', 'V-6893']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
