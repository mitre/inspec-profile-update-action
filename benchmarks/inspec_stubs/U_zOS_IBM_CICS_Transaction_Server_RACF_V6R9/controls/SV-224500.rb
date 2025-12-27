control 'SV-224500' do
  title 'CICS regions are improperly protected to prevent unauthorized propagation of the region userid.'
  desc 'CICS is a transaction-processing product that provides programmers with the facilities to develop interactive applications. Improperly defined or controlled CICS userids (i.e., region, default, and terminal users) may provide an exposure and vulnerability within the CICS environment.  This could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the RACF Data Collection:

-	SENSITVE.RPT(PROPCNTL)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b)	Ensure the CICS region is defined to the PROPCNTL resource class.

c)	If (b) are true, there is NO FINDING.

d)	If (b) is untrue, this is a FINDING.'
  desc 'fix', "Utilize propagation control for each CICS region. 

Under no circumstance should a user's batch job submitted from a CICS region execute under that CICS region's userid. To prevent this from occurring, define a profile in the PROPCNTL resource class for each CICS region. The
following is an example:
RDEFINE PROPCNTL <cics-region-userid> OWNER(ADMIN) AUDIT(ALL(READ))

The PROPCNTL class must be active and RACLISTed for this protection to be in effect:
SETROPTS CLASSACT(PROPCNTL) RACLIST(PROPCNTL)"
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for RACF'
  tag check_id: 'C-26183r520286_chk'
  tag severity: 'medium'
  tag gid: 'V-224500'
  tag rid: 'SV-224500r520288_rule'
  tag stig_id: 'ZCICR041'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26171r520287_fix'
  tag 'documentable'
  tag legacy: ['SV-7193', 'V-6898']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
