control 'SV-224267' do
  title 'CA Auditor resources are not properly defined and protected.'
  desc 'CA Auditor can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to system programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the ACF2 Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZADT0020)
- ACF2CMDS.RPT(RESOURCE) - Alternate report

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZADT0020)

Verify that the access to the LTDMMAIN resource in the PROGRAM resource class is restricted.

___ The ACF2 rules for the resources specify a default access of NONE.

___ The ACF2 rules for the resources are restricted access to system programmers, auditors, and security personnel.'
  desc 'fix', 'The IOA will verify that the LTDMMAIN resource in the PROGRAM resource class is restricted to system programmers, auditors, and security personnel.

The ACF2 rules for the resource specify a default access of NONE. There are ACF2 rules defined and only system programmers, auditors, and security personnel have access.

Example:

SET R(PGM)
$KEY(LTDMMAIN) TYPE(PGM)
 UID(<syspaudt>) ALLOW
 UID(<audtaudt>) ALLOW
 UID(<secaaudt>) ALLOW
 UID(*) PREVENT DATA(SRR FINDING FOR CA AUDITOR)'
  impact 0.5
  ref 'DPMS Target zOS CA Auditor for ACF2'
  tag check_id: 'C-25940r868066_chk'
  tag severity: 'medium'
  tag gid: 'V-224267'
  tag rid: 'SV-224267r868068_rule'
  tag stig_id: 'ZADTA020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-25928r868067_fix'
  tag 'documentable'
  tag legacy: ['SV-32208', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
