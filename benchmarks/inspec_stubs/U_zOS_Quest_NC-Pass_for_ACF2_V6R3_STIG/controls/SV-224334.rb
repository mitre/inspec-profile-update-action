control 'SV-224334' do
  title 'Quest NC-Pass will be used by Highly-Sensitive users.'
  desc 'DISA has directed that Quest NC-Pass extended authentication be implemented on all domains. All users with update and alter access to sensitive system-level data sets and resources, or who possess special security privileges, are required to use NC-Pass for extended authentication.  Typical personnel required to use NC-Pass include, but are not limited to, systems programming, security, operations, network/communications, storage management, and production control.

Improper enforcement of extended authentication through NC-Pass could potentially compromise the operating system, ACP, and customer data.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection:

-	ACF2CMDS.RPT(TSOUSERS)

If all sensitive users requiring NC-Pass validation has the AUTHSUP1 attribute, this is not a finding.

NOTE:	Sensitive users include systems programming personnel, security personnel, and other staff (e.g., DASD management, operations, auditors, technical support, etc.) with access to sensitive resources (e.g., operator commands, ACP privileges, etc.) that can modify the operating system and system software, and review/modify the security environment.'
  desc 'fix', 'The IAO will ensure that sensitive users are properly validated to Quest NC-Pass.

NOTE:	Sensitive users include systems programming personnel, security personnel, and other staff (e.g., DASD management, operations, auditors, technical support, etc.) with access to sensitive resources (e.g., operator commands, ACP privileges, etc.) that can modify the operating system and system software, and review/modify the security environment.

The following attributes must be set for logonids requiring NC-Pass validation:

SET LID
CHANGE logonid AUTHSUP1'
  impact 0.5
  ref 'DPMS Target zOS Quest NC-Pass for ACF2'
  tag check_id: 'C-26011r520793_chk'
  tag severity: 'medium'
  tag gid: 'V-224334'
  tag rid: 'SV-224334r855190_rule'
  tag stig_id: 'ZNCPA020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25999r520794_fix'
  tag 'documentable'
  tag legacy: ['V-17947', 'SV-40869']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
