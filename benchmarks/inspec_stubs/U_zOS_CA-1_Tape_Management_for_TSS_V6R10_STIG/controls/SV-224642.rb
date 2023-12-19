control 'SV-224642' do
  title 'CA 1 Tape Management function and password resources must be properly defined and protected.'
  desc 'CA 1 Tape Management can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.

CA 1 on-line applications offer the capabilities to directly access the CA 1 Tape Management Catalog (TMC) for query and update purposes. CA 1 special tape handling privileges offer the ability to process special tape requirements, such as BLP and foreign tapes. Uncontrolled access to these CA 1 features and facilities may threaten the integrity and availability of the CA 1 tape management system, and compromise the confidentiality of customer data.'
  desc 'check', "Refer to the following report produced by the TSS Data Collection and Data Set and Resource Data Collection:

- TSSCMDS.RPT(WHOOCA1T)
- SENSITVE.RPT(WHOHCA1T)

Refer to the following report produced by the z/OS Data Collection:

- CA1RPT(TMSSECAB)
- CA1RPT(TMSTMVT) - for r11.5 and below
- CA1RPT(TMOOPTxx) - for r12.0 and above
- CA1RPT(TMOSECxx) - for r12.6 and above

Automated Analysis requiring additional analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCA10021)

Ensure that all CA 1 function and password resources are properly protected according to the requirements specified in the CA 1 Function and Password Resources table in the z/OS STIG Addendum.   If the following guidance is true, this is not a finding.

___ The TSS resources and/or generic equivalent as designated in the above table are owned and/or DEFPROT is specified for the resource class.

___ The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

___ The TSS resource logging is specified as designated in the above table.

Note: CA 1 password resources may require additional analysis to ensure access authorization is justified. CA 1 system password is obtained at offset x'18' from the beginning of module TMSTMVT for r11.5 and below and SHUTDWN option specified in the TMOOPTxx for r12.0 and above. CA 1 Online User Passwords can be obtained from TMSSECAB for all releases or TMOSECxx, if present, for r12.6 and above."
  desc 'fix', 'Ensure that the CA 1 function and password resource access is in accordance with those outlined in CA 1 Function and Password Resources table in the zOS STIG Addendum.

Use CA 1 Function and Password Resources and CA 1 Function and Password Resources for TSS tables in the zOS STIG Addendum. These tables list the resources, access requirements, and the resource class for CA 1 Function and Password Resources; ensure the following guidelines are followed:

The TSS resources and/or generic equivalent as designated in the above table are owned or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The TSS resource logging is specified as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(dept-acid) CATAPE(BLPRES) 
TSS PERMIT(tapeaudt) CATAPE(BLPRES) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(syspaudt) CATAPE(BLPRES) ACCESS(UPDATE) ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target zOS CA 1 Tape Management for TSS'
  tag check_id: 'C-26325r868624_chk'
  tag severity: 'medium'
  tag gid: 'V-224642'
  tag rid: 'SV-224642r868625_rule'
  tag stig_id: 'ZCA1T021'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26313r804028_fix'
  tag 'documentable'
  tag legacy: ['SV-40078', 'V-17982']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
