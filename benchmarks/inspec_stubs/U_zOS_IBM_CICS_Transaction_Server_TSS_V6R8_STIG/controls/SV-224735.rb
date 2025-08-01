control 'SV-224735' do
  title 'IBM CICS Transaction Server SPI command resources must be properly defined and protected.'
  desc 'IBM CICS Transaction Server can run with sensitive system privileges, and potentially can circumvent system controls.  Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data.  Many utilities assign resource controls that can be granted to system programmers only in greater than read authority.  Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection and Data Set and Resource Data Collection:

SENSITVE.RPT(WHOHSPI)
TSSCMDS.RPT(WHOOSPI)
TSSCMDS.RPT(#RDT)

Automated Analysis:
Refer to the following report produced by the TSS Data Collection Checklist:

- PDI (ZCIC0021)

Ensure that all IBM CICS Transaction Server resources defined in the IBM CICS-RACF Security Guide are properly protected according to the requirements specified in CICS SPI Resources table in the site security plan, use CICS SPI Resources table in the zOS STIG Addendum as a guide. If the following guidance is true, this is not a finding.

The TSS resources and/or generic equivalent as designated in the above table are owned or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.'
  desc 'fix', 'Ensure that the IBM CICS Transaction Server command resources defined in the IBM CICS-RACF Security Guide access is in accordance with those outlined in CICS SPI Resources table in the site security plan use CICS SPI Resources table in the zOS STIG Addendum as a guide.

These tables list the resources and access requirements for IBM CICS Transaction Server; ensure the following guidelines are followed:


The TSS resources and/or generic equivalent as designated in the above table are owned or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(dept-acid) SPI(ASSOCIAT)
TSS PERMIT(cicsaudt) SPI(ASSOCIAT) ACCESS(READ)
TSS PERMIT(cicuaudt) SPI(ASSOCIAT) ACCESS(READ)
TSS PERMIT(syscsaudt) SPI(ASSOCIAT) ACCESS(READ)'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for TSS'
  tag check_id: 'C-26426r520307_chk'
  tag severity: 'medium'
  tag gid: 'V-224735'
  tag rid: 'SV-224735r855162_rule'
  tag stig_id: 'ZCICT021'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26414r520308_fix'
  tag 'documentable'
  tag legacy: ['SV-43227', 'V-17982']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
