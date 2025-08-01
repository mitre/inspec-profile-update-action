control 'SV-224251' do
  title 'BMC MAINVIEW for z/OS STC data sets are not properly protected.'
  desc 'BMC MAINVIEW for z/OS STC data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', "Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(MVZSTC)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZMVZ0001)

Verify that the accesses to the BMC MAINVIEW for z/OS STC data sets are properly restricted.
 
___ The ACF2 data set rules for the data sets restricts READ access to auditors and authorized users.

___ The ACF2 data set rules for the data sets restricts UPDATE and/or ALTER access to systems programming personnel.

___ The ACF2 data set rules for the data sets restricts UPDATE and/or ALTER access to the BMC MAINVIEW for z/OS's STC(s) and/or batch user(s)."
  desc 'fix', "The ISSO will ensure that update and allocate access to BMC MAINVIEW for z/OS STC data sets is limited to systems programmers and/or BMC MAINVIEW for z/OS's STC(s) and/or batch user(s) only. Read access can be given to auditors and authorized users.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

Data sets to be protected will be: 
SYS3.BMCVIEW (data sets that are altered by the product's STCs, this can be more specific)

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS3)
BMCVIEW.- UID(<syspaudt>) R(A) W(A) A(A) E(A)
BMCVIEW.- UID(<tstcaudt>) R(A) W(A) A(A) E(A)
BMCVIEW.- UID(MAINVIEW STCs) R(A) W(A) A(A) E(A)
BMCVIEW.- UID(<audtaudt>) R(A) E(A)
BMCVIEW.- UID(authorize users) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS BMC MAINVIEW for zOS for ACF2'
  tag check_id: 'C-25924r868204_chk'
  tag severity: 'medium'
  tag gid: 'V-224251'
  tag rid: 'SV-224251r868206_rule'
  tag stig_id: 'ZMVZA001'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-25912r868205_fix'
  tag 'documentable'
  tag legacy: ['V-17067', 'SV-37720']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
