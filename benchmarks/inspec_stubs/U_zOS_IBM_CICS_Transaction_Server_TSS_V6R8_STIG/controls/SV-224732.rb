control 'SV-224732' do
  title 'CICS region logonid(s) must be defined and/or controlled in accordance with the security requirements.'
  desc 'CICS is a transaction-processing product that provides programmers with the facilities to develop interactive applications. Improperly defined or controlled CICS userids (i.e., region, default, and terminal users) may provide an exposure and vulnerability within the CICS environment.  This could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', 'a)       Refer to the following report produced by the z/OS Data Collection:

-	EXAM.RPT(CICSPROC)

Refer to the following reports produced by the TSS Data Collection:

-	TSSCMDS.RPT(@ACID)
-	TSSCMDS.RPT(#STC)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b)       Ensure the following items are in effect for each CICS region ACID.

1)       A unique ACID is associated with the CICS region.
2)       No access to interactive online facilities (e.g., TSO) other than CICS.
3)       CICS region ACID does not have any BYPASS privilege. EXCEPT: NOSUBCHK - REQUIRED FOR CICS REGIONS TO SUBMIT BATCH PROCESSING/JOBS OF THE USER WHO IS LOGGED INTO CICS.
4)       Ensure that each CICS region ACID is associated with a TSS CICS facility.  For example:

TSS ADD(CICS region ACID) MASTFAC(CICS facility)
5)       CICS region is defined in the STC table. For example:

TSS ADD(STC) PROCNAME(CICS region) ACID(CICS ACID)

c)       If (b) are true, this is not a finding.

d)       If (b) are untrue, this is a finding.'
  desc 'fix', 'Review all CICS region, default, and end-user userids to ensure they are defined and controlled as required.

Ensure the following items are in effect for each CICS region ACID: 

      A unique ACID is associated with the CICS region.

      No access to interactive online facilities (e.g., TSO) other than CICS.

      CICS region ACID does not have any BYPASS privilege.

      CICS region ACID is associated with a TSS CICS facility (The IAO will determine the MASTFAC used)

      CICS region is defined in the STC table.

For example:

TSS ADD(STC) PROCNAME(CICS region) ACID(CICS ACID)'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for TSS'
  tag check_id: 'C-26423r520298_chk'
  tag severity: 'medium'
  tag gid: 'V-224732'
  tag rid: 'SV-224732r520300_rule'
  tag stig_id: 'ZCIC0040'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26411r520299_fix'
  tag 'documentable'
  tag legacy: ['SV-7533', 'V-44']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
