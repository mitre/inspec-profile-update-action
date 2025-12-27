control 'SV-225594' do
  title 'Quest NC-Pass will be used by Highly-Sensitive users.'
  desc 'DISA has directed that Quest NC-Pass extended authentication be implemented on all domains. All users with update and alter access to sensitive system-level data sets and resources, or who possess special security privileges, are required to use NC-Pass for extended authentication.  Typical personnel required to use NC-Pass include, but are not limited to, systems programming, security, operations, network/communications, storage management, and production control.

Improper enforcement of extended authentication through NC-Pass could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following reports produced by the TSS Data Collection and Data Set and Resource Data Collection:

-	TSSCMDS.RPT(@ACIDS)
-	TSSCMDS.RPT(@ALL)
-	SENSITVE.RPT(WHOHABS)

If all sensitive users requiring NC-Pass validation has the NCPASS Facility and permitted to the SECURID resource in the ABSTRACT resource class, this is not a finding.

NOTE:	Sensitive users include systems programming personnel, security personnel, and other staff (e.g., DASD management, operations, auditors, technical support, etc.) with access to sensitive resources (e.g., operator commands, ACP privileges, etc.) that can modify the operating system and system software, and review/modify the security environment.'
  desc 'fix', 'The IAO will ensure that sensitive users are properly validated to Quest NC-Pass.

NOTE:	Sensitive users include systems programming personnel, security personnel, and other staff (e.g., DASD management, operations, auditors, technical support, etc.) with access to sensitive resources (e.g., operator commands, ACP privileges, etc.) that can modify the operating system and system software, and review/modify the security environment.

Sensitive users requiring access to NC-PASS must be granted access to the NCPASS Facility and the SECURID resource in the ABSTRACT resource class.  Use the following commands as an example:

TSS ADD(acid) FAC(NCPASS)
TSS PERMIT(acid) ABS(SECURID)'
  impact 0.5
  ref 'DPMS Target zOS Quest NC-Pass for TSS'
  tag check_id: 'C-27294r472581_chk'
  tag severity: 'medium'
  tag gid: 'V-225594'
  tag rid: 'SV-225594r855195_rule'
  tag stig_id: 'ZNCPT020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-27282r472582_fix'
  tag 'documentable'
  tag legacy: ['V-17947', 'SV-40871']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
