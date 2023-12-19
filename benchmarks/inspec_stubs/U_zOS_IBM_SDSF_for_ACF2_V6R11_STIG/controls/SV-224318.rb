control 'SV-224318' do
  title 'IBM System Display and Search Facility (SDSF) HASPINDX data set identified in the INDEX parameter must be properly protected.'
  desc 'IBM System Display and Search Facility (SDSF) HASPINDX data set control the execution, configuration, and security of the SDSF products.  Failure to properly protect access to these data sets could result in unauthorized access.  This exposure may threaten the availability of SDSF, and compromise the confidentiality of customer data.'
  desc 'check', 'If the z/OS operating system is Release 2.2 or higher this is not applicable.

Refer to the following report produced by the Data Set and Resource Data Collection:

-       SENSITVE.RPT(SDSFRPT)

Automated Analysis
Refer to the following report produced by the Data Set and Resource Data Collection:

-       PDI(ZISF0002)

Verify that the accesses to the IBM System Display and Search Facility (SDSF) HASPINDX data set specified on the INDEX control statement in the ISFPARMS statements (identified in the SFSFPARM DD statement of the SDSF stc) are properly restricted. 

If the following guidance is true, this is not a finding.

___       The ACF2 data set rules for the data sets restricts READ access to the auditors.

___       The ACF2 data set rules for the data sets restricts UPDATE access to SDSF Started Tasks.

___       The ACF2 data set rules for the data sets restricts WRITE and/or greater access to systems programming personnel.

Note:       If running z/OS V1R11 or above, with the use of a new JES logical log, the HASPINDX, may not exist and may make this vulnerability not applicable (N/A). However if used the HASPINDX dataset must be restricted.

Note:       If running z/OS V1R11 systems or above and NOT using JES logical log, the HASPINDX data set must be protected.'
  desc 'fix', "Ensure that the HASPINDX dataset identified in the INDEX parameter value of ISFPARMS options statement is restricted as described below.

The HASPINDX data set is used by SDSF when building the SYSLOG panel. This data set contains information related to all SYSLOG jobs and data sets on the spool. Since SDSF dynamically allocates this data set, explicit user access authorization to this data set should not be required. Due to the potentially sensitive data in this data set, access authorization will be restricted.

READ access is restricted to the auditors.

UPDATE access is restricted to SDSF Started Tasks.

WRITE and/or greater access is restricted to systems programming personnel.

Note:       If running z/OS V1R11 or above, with the use of a new JES logical log, the HASPINDX, may not exist and may make this vulnerability not applicable (N/A). However if used the HASPINDX dataset must be restricted.

Note:       If running z/OS V1R11 systems or above and NOT using JES logical log, the HASPINDX data set must be protected.

Data sets to be protected may be:
SYS1.HASPINDX

The following commands are provided as a sample for implementing data set controls:

$KEY(S1H)
$PREFIX(SYS1)
HASPINDX.- UID(syspaudt) R(A) W(A) A(A) E(A)
HASPINDX.- UID(sdsf stc) R(A) W(A) E(A)
HASPINDX.- UID(audtaudt) R(A) E(A)

SET RULE
COMPILE 'ACF2.MVA.DSNRULES(S1H)' STORE"
  impact 0.5
  ref 'DPMS Target zOS IBM SDSF for ACF2'
  tag check_id: 'C-25995r520346_chk'
  tag severity: 'medium'
  tag gid: 'V-224318'
  tag rid: 'SV-224318r520348_rule'
  tag stig_id: 'ZISFA002'
  tag gtitle: 'SRG-OS-000080'
  tag fix_id: 'F-25983r520347_fix'
  tag 'documentable'
  tag legacy: ['SV-40730', 'V-21592']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
