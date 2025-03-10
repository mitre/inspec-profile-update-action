control 'SV-224301' do
  title 'IBM Hardware Configuration Definition (HCD) resources are not properly defined and protected.'
  desc 'Program products can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to program product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to system programmers only in greater than read authority. Resources are also granted to certain non-systems personnel with read only authority.'
  desc 'check', 'a) Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(FACILITY)
- ACF2CMDS.RPT(RESOURCE) - Alternate report

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZHCD0020)

b) Review the following items for the IBM Hardware Configuration Definition (HCD) resources in the FACILITY resource class, TYPE(FAC):

1) The ACF2 rules for the CBD resource specify a default access of NONE.
2) There are no ACF2 rules that allow access to the CBD resource.
3) The ACF2 rules for the CBD.CPC.IOCDS and CBD.CPC.IPLPARM resources are restricted access to systems programming and operations personnel as well as possibly any automated operations batch users with access of READ.
4) The ACF2 rules for the CBD.CPC.IOCDS and CBD.CPC.IPLPARM resources are restricted access to systems programming with access of UPDATE and logged.

c) If any item in (b) is untrue, this is a finding.

d) If all items in (b) are true, this is not a finding.'
  desc 'fix', 'The systems programmer will work with the ISSO to verify that the following are properly specified in the ACP.

1) The ACF2 rules for the CBD resource specify a default access of NONE.
2) There are no ACF2 rules that allow access to the CBD resource.

Example:

SET R(FAC)
$KEY(CBD) TYPE(FAC)
 - UID(*) PREVENT DATA(SRR FINDING FOR HCD)

3) The ACF2 rules for the CBD.CPC.IOCDS and CBD.CPC.IPLPARM resources are restricted access to systems programming and operations personnel as well as possibly any automated operations batch users with access of READ.
4) The ACF2 rules for the CBD.CPC.IOCDS and CBD.CPC.IPLPARM resources are restricted access to systems programming with access of UPDATE and logged.

Example:

SET R(FAC)
$KEY(CBD) TYPE(FAC)
CPC.IOCDS.- UID(syspaudt) SERVICE(READ,UPDATE) LOG
CPC.IOCDS.- UID(operaudt) SERVICE(READ) ALLOW
CPC.IOCDS.- UID(autoaudt) SERVICE(READ) ALLOW
CPC.IPLPARM.- UID(syspaudt) SERVICE(READ,UPDATE) LOG
CPC.IPLPARM.- UID(operaudt) SERVICE(READ) ALLOW
CPC.IPLPARM.- UID(autoaudt) SERVICE(READ) ALLOW'
  impact 0.5
  ref 'DPMS Target zOS HCD for ACF2'
  tag check_id: 'C-25978r868160_chk'
  tag severity: 'medium'
  tag gid: 'V-224301'
  tag rid: 'SV-224301r868162_rule'
  tag stig_id: 'ZHCDA020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25966r868161_fix'
  tag 'documentable'
  tag legacy: ['SV-30582', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
