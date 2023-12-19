control 'SV-225583' do
  title 'NetView resources must be properly defined and protected.'
  desc 'NetView can run with sensitive system privileges, and potentially can circumvent system controls. Failure to properly control access to product resources could result in the compromise of the operating system environment, and compromise the confidentiality of customer data. Many utilities assign resource controls that can be granted to systems programmers only in greater than read authority. Resources are also granted to certain non systems personnel with read only authority.'
  desc 'check', 'Refer to the following report produced by the TSS Data Collection and Data Set and Resource Data Collection:

- SENSITVE.RPT(ZNET0020)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZNET0020)

When SECOPTS.OPERSEC=SAFPW is specified in ZNET0040, this is not applicable. 

Ensure that all NetView resources and/or generic equivalents are properly protected according to the requirements specified in the NetView Resources table in the z/OS STIG Addendum. If the following guidance is true, this is not a finding.

___ The TSS resources and/or generic equivalents as designated in the above table are owned or DEFPROT is specified for the resource class.

___ The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.'
  desc 'fix', "The ISSO will work with the systems programmer to verify that the following are properly specified in the ACP.

(Note: The resource class, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource class, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

When SECOPTS.OPERSEC=SAFPW is specified in ZNET0040, this is not applicable. This can be bypassed. 

Ensure that all NetView resources and/or generic equivalents are properly protected according to the requirements specified in the NetView Resources table in the z/OS STIG Addendum. Additional details can be obtained in the IBM Tivoli NetView for z/OS Security Reference.

Use the NetView Resources table in the z/OS STIG Addendum. This table lists the resources and access requirements for NetView, ensure the following guidelines are followed:

The TSS resources and/or generic equivalents as designated in the above table are owned or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above table.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(dept-acid) NETCMDS(netid)
TSS PERMIT(syspaudt) NETCMDS(netid.luname.ADDCMD) ACCESS(READ)"
  impact 0.5
  ref 'DPMS Target zOS NetView for TSS'
  tag check_id: 'C-27282r868748_chk'
  tag severity: 'medium'
  tag gid: 'V-225583'
  tag rid: 'SV-225583r868750_rule'
  tag stig_id: 'ZNETT020'
  tag gtitle: 'SRG-OS-000018'
  tag fix_id: 'F-27270r868749_fix'
  tag 'documentable'
  tag legacy: ['SV-50926', 'V-17947']
  tag cci: ['CCI-000035', 'CCI-002234']
  tag nist: ['AC-4 (11)', 'AC-6 (9)']
end
