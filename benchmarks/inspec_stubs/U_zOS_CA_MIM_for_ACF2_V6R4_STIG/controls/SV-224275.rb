control 'SV-224275' do
  title 'CA MIM Resource Sharing installation data sets will be properly protected.'
  desc 'CA MIM Resource Sharing installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(MIMRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZMIM0000)

Verify that the accesses to the CA MIM Resource Sharing installation data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The ACF2 data set access authorizations restrict READ access to all authorized users.

___ The ACF2 data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The ACF2 data set access authorizations specify that all (i.e., failures and successes) WRITE and/or greater access are logged.'
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to CA MIM Resource Sharing installation data sets is limited to systems programmers only, and all WRITE and/or greater access is logged. READ access can be given to all authorized users. All failures and successful WRITE and/or greater accesses are logged.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have WRITE and/or greater access and if required that all WRITE and/or greater access is logged. The installing systems programmer will identify if any additional groups have WRITE and/or greater access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation. The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS2.MIMGR.
SYS3.MIMGR.  (data sets that are not altered by product STCs, can be more specific)

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS2)
MIMGR.- UID(<syspaudt>) R(A) W(L) A(L) E(A)
MIMGR.- UID(<tstcaudt>) R(A) W(L) A(L) E(A)
MIMGR.- UID(<audtaudt>) R(A) E(A)
MIMGR.- UID(authorized users) R(A) E(A)
MIMGR.- UID(<audtaudt>) R(A) E(A)
MIMGR.- UID(CA MIM STCs) R(A) E(A)

$KEY(SYS3)
MIMGR.- UID(<syspaudt>) R(A) W(L) A(L) E(A)
MIMGR.- UID(<tstcaudt>) R(A) W(L) A(L) E(A)
MIMGR.- UID(<audtaudt>) R(A) E(A)
MIMGR.- UID(authorized users) R(A) E(A)
MIMGR.- UID(CA MIM STCs) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS CA MIM for ACF2'
  tag check_id: 'C-25948r868195_chk'
  tag severity: 'medium'
  tag gid: 'V-224275'
  tag rid: 'SV-224275r868197_rule'
  tag stig_id: 'ZMIMA000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25936r868196_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-46158']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
