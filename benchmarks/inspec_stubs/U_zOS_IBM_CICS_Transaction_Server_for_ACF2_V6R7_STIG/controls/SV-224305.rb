control 'SV-224305' do
  title 'CICS region logonid(s) must be defined and/or controlled in accordance with the security requirements.'
  desc 'CICS is a transaction-processing product that provides programmers with the facilities to develop interactive applications. Improperly defined or controlled CICS userids (i.e., region, default, and terminal users) may provide an exposure and vulnerability within the CICS environment.  This could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the z/OS Data Collection:

-	EXAM.RPT(CICSPROC)

Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(LOGONIDS)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b)	Ensure the following items are in effect for each CICS region logonid:

1)	A unique logonid is associated with the CICS region.
2)	The CICS region logonid has the ACF2CICS, MUSASS, and NO-SMC attributes specified.
NOTE:	The ACF2CICS privilege will be restricted to CICS region logonids only.
3)	If CICS region submits jobs on behalf of its users, the JOBFROM attribute is specified.
4)	If CICS region has a requirement to update information in the ACF2 database, the MUSUPDT attribute is specified.
5)	Not granted the ACF2 NON-CNCL privilege.
6)	No access to interactive on-line facilities (e.g., TSO) other than CICS.

c)	If (b) are true, this is not a finding.

d)	If (b) is untrue, this is a finding.'
  desc 'fix', "The IAO will ensure that each CICS region is associated with a unique userid and that userid is properly defined.

Review all CICS region, default, and end-user userids to ensure they are defined and controlled as required.

Ensure that the following is defined for each CICS region:

1)	A unique userid is defined.

Use the ACF2 insert command to accomplish this.  A sample command is provided here:

INSERT <cicsregionid> NAME('STC, CICS Region') JOBFROM MUSASS NO-SMC STC ACF2CICS"
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for ACF2'
  tag check_id: 'C-25982r520235_chk'
  tag severity: 'medium'
  tag gid: 'V-224305'
  tag rid: 'SV-224305r520237_rule'
  tag stig_id: 'ZCIC0040'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-25970r520236_fix'
  tag 'documentable'
  tag legacy: ['SV-44', 'V-44']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
