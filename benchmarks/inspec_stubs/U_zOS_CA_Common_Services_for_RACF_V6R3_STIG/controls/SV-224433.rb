control 'SV-224433' do
  title 'CA Common Services installation data sets will be properly protected.'
  desc 'CA Common Services installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(CCSRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZCCS0000)

Verify that the accesses to the CA Common Services installation data sets are properly restricted.  If the following guidance is true, this is not a finding.

___	The RACF data set rules for the data sets restricts READ access to all authorized users.

___	The RACF data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel.

___	The RACF data set rules for the data sets specify that all (i.e., failures and successes) WRITE and/or greater access is logged.

___	The RACF data set rules for the data sets specify UACC(NONE) and NOWARNING.'
  desc 'fix', "The IAO will ensure that WRITE and/or greater access to CA Common Services installation data sets is limited to System Programmers only, and all WRITE and/or greater access is logged.  READ access can be given to all authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged.  He will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected may begin with:
SYS2.CCS.
SYS2A.CCS.
SYS3.CCS.

The following commands are provided as a sample for implementing data set controls:

AD 'sys2.ccs.**' UACC(NONE) OWNER(SYS2) AUDIT(SUCCESS(UPDATE) FAILURES(READ))

PE 'sys2.ccs.**' ID(syspaudt) ACC(A)
PE 'sys2.ccs.**' ID(authorized users/*) ACC(R)"
  impact 0.5
  ref 'DPMS Target zOS CA Common Services for RACF'
  tag check_id: 'C-26110r519578_chk'
  tag severity: 'medium'
  tag gid: 'V-224433'
  tag rid: 'SV-224433r855119_rule'
  tag stig_id: 'ZCCSR000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26098r519579_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-40834']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
