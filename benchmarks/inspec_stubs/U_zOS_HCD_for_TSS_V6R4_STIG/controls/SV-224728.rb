control 'SV-224728' do
  title 'IBM Hardware Configuration Definition (HCD) resources are not properly defined and protected.'
  desc 'Program products can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to program product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non-systems personnel with read only authority.'
  desc 'check', 'a) Refer to the following reports produced by the TSS Data Collection and Data Set and Resource Data Collection:

- TSSCMDS.RPT(WHOOIBMF)
- SENSITVE.RPT(WHOHIBMF)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZHCD0020)

b) Review the following items for the IBM Hardware Configuration Definition (HCD) resources in the IBMFAC resource class:

1) The TSS owner is defined for the CBD resource and/or IBMFAC RDT entry has DEFPROT specified.
2) There are no TSS rules that allow access to the CBD resource.
3) The TSS rules for the CBD.CPC.IOCDS and CBD.CPC.IPLPARM resources are restricted access to systems programming and operations personnel as well as possibly any automated operations batch users with access of READ.
4) The TSS rules for the CBD.CPC.IOCDS and CBD.CPC.IPLPARM resources are restricted access to systems programming with access of UPDATE and logged.

c) If any item in (b) is untrue, this is a finding.

d) If all items in (b) are true, this is not a finding.'
  desc 'fix', 'The systems programmer will work with the ISSO to verify that the following are properly specified in the ACP.

1) The TSS owner is defined for the CBD resources and/or IBMFAC RDT entry has DEFPROT specified.

For example:

TSS ADD(dept-acid)IBMFAC(CBD.)

TSS REP(RDT)RESCLASS(IBMFAC)ATTR(DEFPROT)

2) There are no TSS rules that allow access to the CBD resource.

3) The RACF rules for the CBD.CPC.IOCDS and CBD.CPC.IPLPARM resources are restricted access to systems programming and operations personnel as well as possibly any automated operations batch users with access of READ.

4) The RACF rules for the CBD.CPC.IOCDS and CBD.CPC.IPLPARM resources are restricted access to systems programming with access of UPDATE and logged.

Example:

TSS PERMIT(syspaudt)IBMFAC(CBD.CPC.IOCDS)ACCESS(READ)
TSS PERMIT(operaudt)IBMFAC(CBD.CPC.IOCDS)ACCESS(READ)
TSS PERMIT(autoaudt)IBMFAC(CBD.CPC.IOCDS)ACCESS(READ)
TSS PERMIT(syspaudt)IBMFAC(CBD.CPC.IOCDS) -
	ACCESS(UPDATE)ACTION(AUDIT)
TSS PERMIT(syspaudt)IBMFAC(CBD.CPC.IPLPARM)ACCESS(READ)
TSS PERMIT(operaudt)IBMFAC(CBD.CPC.IPLPARM)ACCESS(READ)
TSS PERMIT(autoaudt)IBMFAC(CBD.CPC.IPLPARM)ACCESS(READ)
TSS PERMIT(syspaudt)IBMFAC(CBD.CPC.IPLPARM) -
	ACCESS(UPDATE)ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target zOS HCD for TSS'
  tag check_id: 'C-26419r870233_chk'
  tag severity: 'medium'
  tag gid: 'V-224728'
  tag rid: 'SV-224728r870235_rule'
  tag stig_id: 'ZHCDT020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26407r870234_fix'
  tag 'documentable'
  tag legacy: ['V-17947', 'SV-30586']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
