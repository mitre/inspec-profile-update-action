control 'SV-224530' do
  title 'ROSCOE resources must be properly defined and protected.'
  desc 'ROSCOE can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality and integrity of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(ZROS0020)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZROS0020)

Ensure that all ROSCOE resources and/or generic equivalent are properly protected according to the requirements specified in CA ROSCOE Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The RACF resource access authorizations restrict access to the appropriate personnel.

___ The RACF resource logging is correctly specified.

___ The RACF resource access authorizations are defined with UACC(NONE) and NOWARNING.'
  desc 'fix', "The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note: The resources and/or resource prefixes identified below are examples of a possible installation. The actual resources and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Ensure that all ROSCOE resources and/or generic equivalent are properly protected according to the requirements specified in CA ROSCOE Resources table in the z/OS STIG Addendum.

Use CA ROSCOE Resources table in the z/OS STIG Addendum. This table lists the resources, access requirements, and logging requirements for ROSCOE ensure the following guidelines are followed:

The RACF resource access authorizations restrict access to the appropriate personnel.

The RACF resource logging is correctly specified.

The RACF resource access authorizations specify UACC(NONE) and NOWARNING.

The following commands are provided as a sample for implementing resource controls:

RDEFINE RO@RES rosid.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
RDEFINE RO@RES rosid.ROSCMD.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
RDEFINE RO@RES rosid.ROSCMD.MONITOR.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
RDEFINE RO@RES rosid.ROSCMD.ETSO UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
RDEFINE RO@RES rosid.ROSCMD.MONITOR.AMS UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))

PE rosid.ROSCMD.ETSO CLASS(RO@RES) ID(*) ACCESS(READ)
PE rosid.ROSCMD.MONITOR.- CLASS(RO@RES) ID(syspaudt) ACCESS(ALTER)
PE rosid.ROSCMD.MONITOR.AMS CLASS(RO@RES) ID(syspaudt) ACCESS(ALTER)
PE rosid.ROSCMD.MONITOR.AMS CLASS(RO@RES) ID(*) ACCESS(READ)
PE rosid.ROSCMD.- CLASS(RO@RES) ID(syspaudt) ACCESS(ALTER)"
  impact 0.5
  ref 'DPMS Target zOS ROSCOE for RACF'
  tag check_id: 'C-26213r868538_chk'
  tag severity: 'medium'
  tag gid: 'V-224530'
  tag rid: 'SV-224530r868542_rule'
  tag stig_id: 'ZROSR020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-26201r868541_fix'
  tag 'documentable'
  tag legacy: ['V-17947', 'SV-23708']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
