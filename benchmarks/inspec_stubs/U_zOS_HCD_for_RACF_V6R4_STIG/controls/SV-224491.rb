control 'SV-224491' do
  title 'IBM Hardware Configuration Definition (HCD) resources are not properly defined and protected.'
  desc 'Program products can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to program product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non-systems personnel with read only authority.'
  desc 'check', 'a) Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(FACILITY)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZHCD0020)

b) Review the following items for the IBM Hardware Configuration Definition (HCD) resources in the FACILITY resource class:

1) The RACF rules for the CBD resource specify a default access of NONE.
2) The RACF rules for the CBD.CPC.IOCDS and CBD.CPC.IPLPARM resources restrict access to systems programming and operations personnel as well as possibly any automated operations batch users with access of READ.
3) The RACF rules for the CBD.CPC.IOCDS and CBD.CPC.IPLPARM resources are restricted access to systems programming with access of UPDATE and logged.
4) All RACF rules are defined with UACC(NONE).

c) If any item in (b) is untrue, this is a finding.

d) If all items in (b) are true, this is not a finding.'
  desc 'fix', "The systems programmer will work with the ISSO to verify that the following are properly specified in the ACP.

1) The RACF rules for the CBD resource specify a default access of NONE.
2) There are no RACF rules that allow access to the CBD resource.

Example:

rdef facility cbd.** uacc(none) owner(admin) audit(failure(read)) -
data('added per PDI ZHCD0020') 

3) The RACF rules for the CBD.CPC.IOCDS and CBD.CPC.IPLPARM resources are restricted access to systems programming and operations personnel as well as possibly any automated operations batch users with access of READ.
4) The RACF rules for the CBD.CPC.IOCDS and CBD.CPC.IPLPARM resources are restricted access to systems programming with access of UPDATE and logged.
5) All RACF rules are defined with UACC(NONE).

Example:

rdef facility cbd.cpc.iocds.** uacc(none) owner(admin) -
	audit(success(update) failures(read)) -
	data('added per PDI ZHCD0020') 
rdef facility cbd.cpc.iplparm.** uacc(none) owner(admin) -
	audit(success(update) failures(read)) -
	data('added per PDI ZHCD0020') 

pe cbd.cpc.iocds.** cl(facility) id(syspaudt) acc(u)
pe cbd.cpc.iocds.** cl(facility) id(operaudt) acc(r)
pe cbd.cpc.iocds.** cl(facility) id(autoaudt) acc(r)
pe cbd.cpc.iplparm.** cl(facility) id(syspaudt) acc(u)
pe cbd.cpc.iplparm.** cl(facility) id(operaudt) acc(r)
pe cbd.cpc.iplparm.** cl(facility) id(autoaudt) acc(r)

setr racl(facility) ref"
  impact 0.5
  ref 'DPMS Target zOS HCD for RACF'
  tag check_id: 'C-26174r870226_chk'
  tag severity: 'medium'
  tag gid: 'V-224491'
  tag rid: 'SV-224491r870227_rule'
  tag stig_id: 'ZHCDR020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26162r868403_fix'
  tag 'documentable'
  tag legacy: ['SV-30583', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
