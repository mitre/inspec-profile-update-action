control 'SV-255939' do
  title 'IBM Integrated Crypto Service Facility (ICSF) STC data sets must be properly protected.'
  desc 'IBM Integrated Crypto Service Facility (ICSF) STC data sets have the ability to use privileged functions and/or have access to sensitive data.  Failure to properly restrict access to their data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Verify that access to the IBM Integrated Crypto Service Facility (ICSF) STC data sets are properly restricted. The data sets to be protected are identified in the data set referenced in the CSFPARM DD statement of the ICSF started task(s) and/or batch job(s); the entries for CKDSN and PKDSN specify the data sets.

If the RACF data set access authorizations do not restrict READ access to auditors, this is a finding

If the  RACF data set access authorizations do not restrict WRITE and/or greater access to systems programming personnel, this is a finding.

If the RACF data set access authorizations do not  restrict WRITE and/or greater access to the product STC(s) and/or batch job(s), this is a finding.'
  desc 'fix', "Ensure that WRITE and/or greater access to IBM Integrated Crypto Service Facility (ICSF) STC and/or batch data sets are limited to system programmers and ICSF STC and/or batch jobs only.  READ access can be given to auditors at the ISSOs discretion.

The installing Systems Programmer will identify and document the product data sets and categorize them according to who will have what type of access and if required, which type of access is logged.  The installing systems programmer will identify any additional groups requiring access to specific data sets, and once documented the installing systems programmer will work with the ISSO to confirm that they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

The data sets to be protected are identified in the data set referenced in the CSFPARM DD statement of the ICSF started task(s) and/or batch job(s); the entries for CKDSN and PKDSN specify the data sets.

Note: Currently on most CSD systems, the CKDSN specifies SYS3.CSF.CKDS, and PKDSN specifies SYS3.CSF.PKDS.

The following commands are provided as a sample for implementing data set controls:

ad 'sys3.csf.**' uacc(none) owner(sys3) -
audit(failures(read)) -
data('ICSF Output Data')
pe 'sys3.csf.**' id(syspaudt) acc(a)
pe 'sys3.csf.**' id(tstcaudt) acc(a)
pe 'sys3.csf.**' id(icsfstc) acc(a)
pe 'sys3.csf.**' id(audtaudt) acc(r)"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-59616r881307_chk'
  tag severity: 'medium'
  tag gid: 'V-255939'
  tag rid: 'SV-255939r881309_rule'
  tag stig_id: 'RACF-IC-000030'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-59559r881308_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
