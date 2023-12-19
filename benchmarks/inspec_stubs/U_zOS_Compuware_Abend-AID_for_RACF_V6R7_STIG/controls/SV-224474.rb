control 'SV-224474' do
  title 'Compuware Abend-AID user data sets must be properly protected.'
  desc 'Compuware Abend-AID user data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(AIDUSER)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZAID0002)

Verify that the accesses to the following Compuware Abend-AID user data sets are properly restricted.
Region dump datasets
Report databases
Source listing files/source listing shared directories
      
If the following guidance is true, this is not a finding.

___ The RACF data set rules for the listed data sets restricts READ access to auditors.

___ The RACF data set rules for the listed data sets restricts WRITE and/or greater access to systems programming personnel.

___ The RACF data set rules for the listed data sets restricts WRITE and/or greater access to the Compuware Abend-AID's STC(s) and/or batch user(s).

___ The RACF data set rules for the listed data sets restricts CONTROL access to application development programmers and Application Production Support Team members.

___ The RACF data set rules for the listed data sets specify UACC(NONE) and NOWARNING."
  desc 'fix', "Ensure that WRITE and/or greater access to Compuware Abend-AID User data sets listed is limited to systems programmers and/or Compuware Abend-AID's STC(s) and/or batch user(s) only. Ensure that CONTROL access to Compuware Abend-AID User data sets listed is limited to application development programmers and Application Production Support Team members. READ access can be given to auditors.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be:

Region dump datasets
Report databases
Source listing files/source listing shared directories

The following commands are provided as a sample for implementing data set controls:

AD 'sys3.abendaid.shared.**' UACC(NONE) OWNER(SYS3) AUDIT(SUCCESS(UPDATE) FAILURES(READ))
AD 'sys3.abendaid.reportdb.**' UACC(NONE) OWNER(SYS3) AUDIT(SUCCESS(UPDATE) FAILURES(READ))

PE 'sys3.abendaid.reportdb.**' ID(syspaudt) ACC(A)
PE 'sys3.abendaid.reportdb.**' ID(tstcaudt) ACC(A)
PE 'sys3.abendaid.reportdb.**' ID(ABEND-AID STCs) ACC(A)
PE 'sys3.abendaid.reportdb.**' ID(audtaudt) ACC(R)
PE 'sys3.abendaid.reportdb.**' ID(appdaudt) ACC(CONTROL)
PE 'sys3.abendaid.reportdb.**' ID(appsaudt) ACC(CONTROL) 
PE 'sys3.abendaid.shared.**' ID(syspaudt) ACC(A)
PE 'sys3.abendaid.shared.**' ID(tstcaudt) ACC(A)
PE 'sys3.abendaid.shared.**' ID(ABEND-AID STCs) ACC(A)
PE 'sys3.abendaid.shared.**' ID(audtaudt) ACC(R)
PE 'sys3.abendaid.shared.**' ID(appdaudt) ACC(CONTROL)
PE 'sys3.abendaid.shared.**' ID(appsaudt) ACC(CONTROL)"
  impact 0.5
  ref 'DPMS Target zOS Compuware Abend-AID for RACF'
  tag check_id: 'C-26157r868284_chk'
  tag severity: 'medium'
  tag gid: 'V-224474'
  tag rid: 'SV-224474r868286_rule'
  tag stig_id: 'ZAIDR002'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-26145r868285_fix'
  tag 'documentable'
  tag legacy: ['SV-75839', 'V-21592']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
