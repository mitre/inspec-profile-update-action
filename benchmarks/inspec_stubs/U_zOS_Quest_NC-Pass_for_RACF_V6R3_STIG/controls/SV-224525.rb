control 'SV-224525' do
  title 'Quest NC-Pass will be used by Highly-Sensitive users.'
  desc 'DISA has directed that Quest NC-Pass extended authentication be implemented on all domains. All users with update and alter access to sensitive system-level data sets and resources, or who possess special security privileges, are required to use NC-Pass for extended authentication.  Typical personnel required to use NC-Pass include, but are not limited to, systems programming, security, operations, network/communications, storage management, and production control.

Improper enforcement of extended authentication through NC-Pass could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following reports produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)
-	RACFCMDS.RPT(LISTGRP)

If the SECURID group is defined and all sensitive users are connected to the SECURID group, this is not a finding.

NOTE:	Sensitive users include systems programming personnel, security personnel, and other staff (e.g., DASD management, operations, auditors, technical support, etc.) with access to sensitive resources (e.g., operator commands, ACP privileges, etc.) that can modify the operating system and system software, and review/modify the security environment.'
  desc 'fix', 'The IAO will ensure that sensitive users are properly validated to Quest NC-Pass.

NOTE:	Sensitive users include systems programming personnel, security personnel, and other staff (e.g., DASD management, operations, auditors, technical support, etc.) with access to sensitive resources (e.g., operator commands, ACP privileges, etc.) that can modify the operating system and system software, and review/modify the security environment.

Ensure SECURID is defined to RACF.  Use the following RACF AddGroup command:

AG SECURID SUPGROUP(ADMIN) OWNER(ADMIN)

Ensure sensitive users that require NC-Pass validation is connected to the SECURID group.  Use the following command:

CO userid GROUP(SECURID) OWNER(SECURID)'
  impact 0.5
  ref 'DPMS Target zOS Quest NC-Pass for RACF'
  tag check_id: 'C-26208r520805_chk'
  tag severity: 'medium'
  tag gid: 'V-224525'
  tag rid: 'SV-224525r855192_rule'
  tag stig_id: 'ZNCPR020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26196r520806_fix'
  tag 'documentable'
  tag legacy: ['SV-40870', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
