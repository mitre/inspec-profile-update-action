control 'SV-224313' do
  title 'Sensitive CICS transactions are not protected in accordance with the proper security requirements.'
  desc 'Sensitive CICS transactions offer the ability to circumvent transaction level controls for accessing resources under CICS.  These transactions must be protected so that only authorized users can access them.  Unauthorized use can result in the compromise of the confidentiality, integrity, and availability of the operating system or customer data.'
  desc 'check', 'a)	Refer to the following report produced by the z/OS Data Collection:

	-	EXAM.RPT(CICSPROC)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b)	Browse the ACF2/CICS data set allocated by the ACF2PARM DD statement in the JCL of each CICS procedure.

c)	If the PROTLIST parameter is not specified for all CICS regions, there is NO FINDING.

d)	If the PROTLIST parameter is specified for any CICS region, this is a FINDING.'
  desc 'fix', 'The Systems Programmer and IAO will ensure the ACF2/CICS parameter PROTLIST is not coded.

Browse the ACF2/CICS data set allocated by the ACF2PARM DD statement in the JCL of each CICS procedure.

Make sure the PROTLIST parameter is not specified for all CICS regions.'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for ACF2'
  tag check_id: 'C-25990r520259_chk'
  tag severity: 'medium'
  tag gid: 'V-224313'
  tag rid: 'SV-224313r855160_rule'
  tag stig_id: 'ZCICA025'
  tag gtitle: 'SRG-OS-000324'
  tag fix_id: 'F-25978r520260_fix'
  tag 'documentable'
  tag legacy: ['SV-7191', 'V-6896']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
