control 'SV-224114' do
  title 'BMC CONTROL-M installation data sets will be properly protected.'
  desc 'BMC CONTROL-M installation data sets have the ability to use privileged functions and/or have access to sensitive data. Failure to properly restrict access to these data sets could result in violating the integrity of the base product which could result in compromising the operating system or sensitive data.'
  desc 'check', 'Refer to the following report produced by the Data Set and Resource Data Collection:

- SENSITVE.RPT(CTMRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

- PDI(ZCTM0000)

Verify that the accesses to the BMC CONTROL-M installation data sets are properly restricted. If the following guidance is true, this is not a finding.
 
___ The ACF2 data set access authorizations restrict READ access to auditors, automated operations, BMC users, operations, production control and scheduling personnel (domain level and decentralized), and BMC STCs and/or batch users.

___ The ACF2 data set access authorizations restrict WRITE and/or greater access to systems programming personnel.

___ The ACF2 data set access authorizations specify that all (i.e., failures and successes) WRITE and/or greater access are logged.'
  desc 'fix', "The ISSO will ensure that WRITE and/or greater access to BMC CONTROL-M installation data sets are limited to systems programmers only, and all WRITE and/or greater access is logged. READ access can be given to auditors, automated operations, BMC users, operations, production control and scheduling personnel (domain level and decentralized), and BMC STCs and/or batch users. All failures and successful WRITE and/or greater accesses are logged.

The installing systems programmer will identify and document the product data sets and categorize them according to who will have update and alter access and if required that all update and allocate access is logged. The installing systems programmer will identify if any additional groups have update and/or alter access for specific data sets, and once documented will work with the ISSO to ensure they are properly restricted to the ACP (Access Control Program) active on the system.

(Note: The data sets and/or data set prefixes identified below are examples of a possible installation.  The actual data sets and/or prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Data sets to be protected will be: 
SYS2.IOA.*.CTMI.

The following commands are provided as a sample for implementing data set controls: 

$KEY(SYS2)
IOA.-.CTMI.- UID(<syspaudt>) R(A) W(L) A(L) E(A)
IOA.-.CTMI.- UID(<audtaudt>) R(A) E(A)
IOA.-.CTMI.- UID(<autoaudt>) R(A) E(A)
IOA.-.CTMI.- UID(<bmcuser>) R(A) E(A)
IOA.-.CTMI.- UID(<dpcsaudt>) R(A) E(A)
IOA.-.CTMI.- UID(<operaudt>) R(A) E(A)
IOA.-.CTMI.- UID(<pcspaudt>) R(A) E(A)
IOA.-.CTMI.- UID(CONTROLM) R(A) E(A)"
  impact 0.5
  ref 'DPMS Target zOS BMC CONTROL-M for ACF2'
  tag check_id: 'C-25787r868130_chk'
  tag severity: 'medium'
  tag gid: 'V-224114'
  tag rid: 'SV-224114r868132_rule'
  tag stig_id: 'ZCTMA000'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25775r868131_fix'
  tag 'documentable'
  tag legacy: ['V-16932', 'SV-31897']
  tag cci: ['CCI-000213', 'CCI-002234']
  tag nist: ['AC-3', 'AC-6 (9)']
end
