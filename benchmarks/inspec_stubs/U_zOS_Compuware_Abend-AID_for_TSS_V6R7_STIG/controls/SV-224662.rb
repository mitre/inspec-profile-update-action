control 'SV-224662' do
  title 'Compuware Abend-AID user data sets must be properly protected.'
  desc 'Compuware Abend-AID user data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(AIDUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZAID0002)

Verify that the accesses to the following Compuware Abend-AID user data sets are properly restricted:
Region dump datasets
Report databases
Source listing files/source listing shared directories

If the following guidance is true, this is not a finding.

___ The TSS data set rules for the listed data sets restricts READ access to auditors.

___ The TSS data set rules for the listed data sets restricts WRITE and/or greater access to systems programming personnel.

___ The TSS data set rules for the listed data sets restricts WRITE and/or greater access to the Compuware Abend-AID's STC(s) and/or batch user(s).

___ The TSS data set rules for the listed data sets restricts CONTROL access to Application Development Programmers and Application Production Support Team members."
  desc 'fix', "Ensure that WRITE and/or greater access to Compuware Abend-AID User data sets listed is limited to systems programmers and Compuware Abend-AID's STC(s) and/or batch user(s) only. Ensure that CONTROL access to Compuware Abend-AID User data sets listed is limited to Application Development Programmers and Application Production Support Team members. READ access can be given to auditors.

 
(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be:
Region dump datasets
Report databases
Source listing files/source listing shared directories

The following commands are provided as a sample for implementing data set controls:

TSS ADD(SYS3) DSN(SYS3.)  

TSS PERMIT(syspaudt) DSN(SYS3.ABENDAID.REPORTDB) ACCESS(ALL)
TSS PERMIT(tstcaudt) DSN(SYS3.ABENDAID.REPORTDB) ACCESS(ALL)
TSS PERMIT(ABEND-AID STCs) DSN(SYS3.ABENDAID.REPORTDB) ACCESS(ALL)
TSS PERMIT(audtaudt) DSN(SYS3.ABENDAID.REPORTDB) ACCESS(READ)
TSS PERMIT(appdaudt) DSN(SYS3.ABENDAID.REPORTDB) ACCESS(CONTROL)
TSS PERMIT(appsaudt) DSN(SYS3.ABENDAID.REPORTDB) ACCESS(CONTROL)   
TSS PERMIT(syspaudt) DSN(SYS3.ABENDAID.SHARED) ACCESS(ALL)
TSS PERMIT(tstcaudt) DSN(SYS3.ABENDAID.SHARED) ACCESS(ALL)
TSS PERMIT(ABEND-AID STCs) DSN(SYS3.ABENDAID.SHARED) ACCESS(ALL)
TSS PERMIT(audtaudt) DSN(SYS3.ABENDAID.SHARED) ACCESS(READ)
TSS PERMIT(appdaudt) DSN(SYS3.ABENDAID.SHARED) ACCESS(CONTROL)
TSS PERMIT(appsaudt) DSN(SYS3.ABENDAID.SHARED) ACCESS(CONTROL)"
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for TSS'
  tag check_id: 'C-26345r868606_chk'
  tag severity: 'medium'
  tag gid: 'V-224662'
  tag rid: 'SV-224662r868608_rule'
  tag stig_id: 'ZAIDT002'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26333r868607_fix'
  tag 'documentable'
  tag legacy: ['SV-75841', 'V-21592']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
