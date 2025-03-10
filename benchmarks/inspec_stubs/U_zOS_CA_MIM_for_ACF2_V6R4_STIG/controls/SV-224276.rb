control 'SV-224276' do
  title 'CA MIM Resource Sharing STC data sets will be properly protected.'
  desc 'CA MIM Resource Sharing STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.omising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(MIMSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZMIM0001)

Verify that the accesses to the CA MIM Resource Sharing STC data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The ACF2 data set access authorizations restrict READ access to auditors and authorized users.

___ The ACF2 data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The ACF2 data set access authorizations restrict WRITE and/or greater access to the CA MIM Resource Sharing's STC(s) and/or batch user(s)."
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to CA MIM Resource Sharing STC data sets is limited to systems programmers and/or CA MIM Resource Sharing's STC(s) and/or batch user(s) only. Read access can be given to auditors and authorized users.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged. The installing systems programmer will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS3.MIMGR.  (Data sets that are altered by the product's STCs, this can be more specific.)

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS3)
MIMGR.- UID(<syspaudt>) R(A) W(A) A(A) E(A)
MIMGR.- UID(<tstcaudt>) R(A) W(A) A(A) E(A)
MIMGR.- UID(CA MIM STCs) R(A) W(A) A(A) E(A)
MIMGR.- UID(<audtaudt>) R(A) E(A)
MIMGR.- UID(authorized users) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS CA MIM for ACF2'
  tag check_id: 'C-25949r868198_chk'
  tag severity: 'medium'
  tag gid: 'V-224276'
  tag rid: 'SV-224276r868200_rule'
  tag stig_id: 'ZMIMA001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-25937r868199_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-46163']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
