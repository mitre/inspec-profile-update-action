control 'SV-224498' do
  title 'IBM CICS Transaction Server SPI command resources must be properly defined and protected.'
  desc 'IBM CICS Transaction Server can run with sensitive system privileges, and potentially can circumvent system controls.  Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data.  Many utilities assign resource controls that can be granted to system programmers only in greater than read authority.  Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

SENSITVE.RPT(CCICSCMD)
SENSITVE.RPT(VCICSCMD)

Automated Analysis:
Refer to the following report produced by the RACF Data Collection Checklist:
- PDI (ZCIC0021)

Ensure that all IBM CICS Transaction Server resources defined in the IBM CICS-RACF Security Guide are properly protected according to the requirements specified in CICS SPI Resources table in the site security plan, use CICS SPI Resources table in the zOS STIG Addendum as a guide. If the following guidance is true, this is not a finding.

The RACF resources and/or generic equivalent as designated in the above table are defined with a default access of NONE.

The RACF resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The RACF resource rules for the resources designated in the above table specify UACC(NONE) and NOWARNING.'
  desc 'fix', 'Ensure that the IBM CICS Transaction Server command resources defined in the IBM CICS-RACF Security Guide access is in accordance with those outlined in the site security plan, use CICS SPI Resources table in the zOS STIG Addendum as a guide. These tables list the resources and access requirements for IBM CICS Transaction Server; ensure the following guidelines are followed:

The RACF resources and/or generic equivalent as designated in the above table are defined with a default access of NONE.

The RACF resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The RACF resource rules for the resources designated in the above table specify UACC(NONE) and NOWARNING.

The following commands are provided as a sample for implementing resource controls:

RDEFINE CCICSCMD ASSOCIATION.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
PERMIT ASSOCIATION.** CLASS(CCICSCMD) ACCESS(READ) ID(cicsaudt)
PERMIT ASSOCIATION.** CLASS(CCICSCMD) ACCESS(READ) ID(cicuaudt)
PERMIT ASSOCIATION.** CLASS(CCICSCMD) ACCESS(READ) ID(syscaudt)'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for RACF'
  tag check_id: 'C-26181r520280_chk'
  tag severity: 'medium'
  tag gid: 'V-224498'
  tag rid: 'SV-224498r855161_rule'
  tag stig_id: 'ZCICR021'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26169r520281_fix'
  tag 'documentable'
  tag legacy: ['SV-43225', 'V-17982']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
