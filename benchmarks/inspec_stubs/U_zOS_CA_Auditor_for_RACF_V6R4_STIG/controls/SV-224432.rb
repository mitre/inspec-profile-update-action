control 'SV-224432' do
  title 'CA Auditor resources are not properly defined and protected.'
  desc 'CA Auditor can run with sensitive system privileges, and potentially can circumvent system controls.  Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data.  Many utilities assign resource controls that can be granted to system programmers only in greater than read authority.  Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

-	SENSITVE.RPT(ZADT0020)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-	PDI(ZADT0020)

Verify that the access to the LTDMMAIN resource in the PROGRAM resource class is restricted.

___	The RACF rules for the resources specify a default access of NONE.

___	The RACF rules for the resources are restricted access to sytem programmers, auditors, and security personnel.

___	All RACF rules are defined with UACC(NONE).'
  desc 'fix', "The IOA will verify that the LTDMMAIN resource in the PROGRAM resource class is restricted to sytem programmers, auditors, and security personnel.

The RACF rules for the LTDMMAIN resource specify a default access of NONE and no RACF rules that allow access to the LTDMMAIN resource.

Example:

rdef program LTDMMAIN uacc(none) owner(admin) audit(failures(read)) -
data('added per PDI ZADT0020') 

The RACF rules for the LTDMMAIN resource is restricted access to system programmers, auditors, and security personnel with access of READ.  All RACF rules are defined with UACC(NONE).

Example:

rdef program ltdmmain -                                
 addmem('SYS2A.EXAMINE.V120SP01.CAILIB'//nopadchk) -   
 data('Required by SRR PDI ZADTR020') -                
 audit(failures(read)) uacc(none) owner(admin)              
pe LTDMMAIN cl(program) id(syspaudt) acc(r)
pe LTDMMAIN cl(program) id(audtaudt) acc(r)
pe LTDMMAIN cl(program) id(secaaudt) acc(r)

setr when(program) ref"
  impact 0.5
  ref 'DPMS Target zOS CA Auditor for RACF'
  tag check_id: 'C-26109r519560_chk'
  tag severity: 'medium'
  tag gid: 'V-224432'
  tag rid: 'SV-224432r855115_rule'
  tag stig_id: 'ZADTR020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26097r519561_fix'
  tag 'documentable'
  tag legacy: ['V-17947', 'SV-32209']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
