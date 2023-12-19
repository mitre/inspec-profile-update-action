control 'SV-224736' do
  title 'CICS userids are not defined and/or controlled in accordance with proper security requirements.'
  desc 'CICS is a transaction-processing product that provides programmers with the facilities to develop interactive applications. Improperly defined or controlled CICS userids (i.e., region, default, and terminal users) may provide an exposure and vulnerability within the CICS environment.  This could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', 'a)	Refer to the following report produced by the TSS Data Collection:

-	TSSCMDS.RPT(WHOOPROP)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b)	Ensure the CICS region is defined to the PROPCNTL resource class.

c)	If (b) are true, there is NO FINDING.

d)	If (b) is untrue, this is a FINDING.'
  desc 'fix', 'Ensure the CICS region is defined to the PROPCNTL resource class.

Example:

TSS ADDTO(owning acid) PROPCNTL(CICS region acid)'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for TSS'
  tag check_id: 'C-26427r520310_chk'
  tag severity: 'medium'
  tag gid: 'V-224736'
  tag rid: 'SV-224736r520312_rule'
  tag stig_id: 'ZCICT041'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26415r520311_fix'
  tag 'documentable'
  tag legacy: ['SV-7525', 'V-7121']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
