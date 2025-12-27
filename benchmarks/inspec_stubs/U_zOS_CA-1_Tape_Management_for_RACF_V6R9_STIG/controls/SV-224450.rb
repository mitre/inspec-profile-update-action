control 'SV-224450' do
  title 'CA 1 Tape Management installation data sets must be properly protected.'
  desc 'CA 1 Tape Management installation data sets have the ability to use privileged functions and/or have access to sensitive data.  Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-       SENSITVE.RPT(CA1PROD)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-       PDI(ZCA10000)

Verify that the accesses to the CA 1 Tape Management installation data sets are properly restricted. If the following guidance is true, this is not a finding.

___       The RACF data set rules for the data sets restricts READ access to all authorized users.

___       The RACF data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel.

___       The RACF data set rules for the data sets specify that all (i.e., failures and successes) WRITE and/or greater access is logged.

___       The RACF data set rules for the data sets specify UACC(NONE) and NOWARNING.'
  desc 'fix', "Ensure that WRITE and/or greater access to CA 1 Tape Management installation data sets is limited to System Programmers only, and all WRITE and/or greater access is logged. READ access can be given to all authorized users.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged. He will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented he will work with the IAO to see that they are properly restricted to the ACP (Access Control Program) active on the system.

The following is an example of the type of data sets to be protected:
SYS2.CA1.
SYS2A.CA1.*.CAILIB
SYS2A.CA1.*.CAILPA
Or
SYS2A.CA1.*.CTAPLINK
SYS3.CA1.
SYS3A.CA1.*.CAILIB
Or
SYS3A.CA1.*.CTAPLINK
SYS3A.CA1.*.CTAPLPA

The following commands are provided as a sample for implementing data set controls:

AD 'sys2.ca1.v**' UACC(NONE) OWNER(SYS2) AUDIT(SUCCESS(UPDATE) FAILURES(READ))
AD 'sys2a.ca1.v*.cailib.**' UACC(NONE) OWNER(SYS2A) AUDIT(SUCCESS(UPDATE) FAILURES(READ))
AD 'sys2a.ca1.v*.cailpa.**' UACC(NONE) OWNER(SYS2A) AUDIT(SUCCESS(UPDATE) FAILURES(READ))
Or
AD 'sys2a.ca1.v*.ctaplink.**' UACC(NONE) OWNER(SYS2A) AUDIT(SUCCESS(UPDATE) FAILURES(READ))
AD 'sys3.ca1.**' UACC(NONE) OWNER(SYS3) AUDIT(SUCCESS(UPDATE) FAILURES(READ))
AD 'sys3a.ca1.v*.cailib.**' UACC(NONE) OWNER(SYS3A) AUDIT(SUCCESS(UPDATE) FAILURES(READ))
Or
AD 'sys3a.ca1.v*.ctaplink.**' UACC(NONE) OWNER(SYS3A) AUDIT(SUCCESS(UPDATE) FAILURES(READ))
AD 'sys3a.ca1.v*.ctaplpa.**' UACC(NONE) OWNER(SYS3A) AUDIT(SUCCESS(UPDATE) FAILURES(READ))

PE 'sys2.ca1.v**' ID(syspaudt) ACC(A)
PE 'sys2.ca1.v**' ID(authorized users/*) ACC(R)
PE 'sys2a.ca1.v*.cailib.**' ID(syspaudt) ACC(A)
PE 'sys2a.ca1.v*.cailib.**' ID(authorized users/*) ACC(R)
PE 'sys2a.ca1.v*.cailpa.**' ID(syspaudt) ACC(A)
PE 'sys2a.ca1.v*.cailpa.**' ID(authorized users/*) ACC(R)
Or
PE 'sys2a.ca1.v*.ctaplink.**' ID(syspaudt) ACC(A)
PE 'sys2a.ca1.v*.ctaplink.**' ID(authorized users/*) ACC(R)
PE 'sys3.ca1.v**' ID(syspaudt) ACC(A)
PE 'sys3.ca1.v**' ID(authorized users/*) ACC(R)
PE 'sys3a.ca1.v*.cailib.**' ID(syspaudt) ACC(A)
PE 'sys3a.ca1.v*.cailib.**' ID(authorized users/*) ACC(R)
Or
PE 'sys3a.ca1.v*.ctaplink.**' ID(syspaudt) ACC(A)
PE 'sys3a.ca1.v*.ctaplink.**' ID(authorized users/*) ACC(R)
PE 'sys3a.ca1.v*.ctaplpa.**' ID(syspaudt) ACC(A)
PE 'sys3a.ca1.v*.ctaplpa.**' ID(authorized users/*) ACC(R)"
  impact 0.5
  ref 'DPMS Target zOS CA 1 Tape Management for RACF'
  tag check_id: 'C-26127r519485_chk'
  tag severity: 'medium'
  tag gid: 'V-224450'
  tag rid: 'SV-224450r519487_rule'
  tag stig_id: 'ZCA1R000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26115r519486_fix'
  tag 'documentable'
  tag legacy: ['SV-40068', 'V-16932']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
