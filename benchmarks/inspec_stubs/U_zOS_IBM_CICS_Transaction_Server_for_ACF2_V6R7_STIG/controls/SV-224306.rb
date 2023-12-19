control 'SV-224306' do
  title 'CICS default logonid(s) must be defined and/or controlled in accordance with the security requirements.'
  desc 'CICS is a transaction-processing product that provides programmers with the facilities to develop interactive applications. Improperly defined or controlled CICS userids (i.e., region, default, and terminal users) may provide an exposure and vulnerability within the CICS environment. This could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', "a) Refer to the following report produced by the z/OS Data Collection:

- EXAM.RPT(CICSPROC)

Refer to the following report produced by the ACF2 Data Collection:

- ACF2CMDS.RPT(LOGONIDS)
- ACF2CMDS.RPT(RESOURCE)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b) Ensure the following items are in effect for the CICS default logonid(s) (i.e., Browse the ACF2PARM DD statement for DEFAULT TERMINAL=<parameter> and DEFAULT NONTERMINAL=nnnnnnnn):

1) Not granted the ACF2 NON-CNCL privilege.
2) No access to interactive on-line facilities (e.g., TSO) other than CICS.
3) IDLE(15) field is set to 15 minutes.
4) A system's default time for terminal lock-out or session termination may be lengthened to 30 minutes at the discretion of the ISSM. The ISSM will maintain the documentation for each system with a time-out adjusted beyond the 15-minute recommendation to explain the basis for this decision.

5) Restricted from accessing all data sets and resources with the following exceptions:

(a) Non-restricted CICS transactions (e.g., CESF, CESN, 'good morning' transaction, etc.)
(b) If applicable, resources necessary to operate in an intersystem communication (ISC) environment (i.e., LU6.1, LU6.2, and MRO)

(c) If all items in (b) are true, this is not a finding.
(d) If any item in (b) is untrue, this is a finding."
  desc 'fix', "Ensure that the default CICS user is restricted and properly defined.

Ensure the following items are in effect for the CICS default logonid(s) (i.e., Browse the ACF2PARM DD statement for DEFAULT TERMINAL=<parameter> and DEFAULT NONTERMINAL=nnnnnnnn):

Not granted the ACF2 NON-CNCL privilege.
Use the ACF2 LIST command to display the default CICS userid.

Example:
SET LID
LIST CICS
CHANGE CICS NONON-CNCL

No access to interactive online facilities (e.g., TSO) other than CICS.

Use the ACF2 LIST command to display the default CICS userid.

Example:
SET LID
LIST CICS
CHANGE CICS NOTSO

IDLE(15) field is set to 15 minutes, up to 30 with justification.
Use the ACF2 LIST command to display the default CICS userid.

Example:

SET LID
LIST CICS
CHANGE CICS IDLE(15) up to 30 with justification

Restricted from accessing all data sets and resources with the following exceptions:

Non-restricted CICS transactions (e.g., CESF, CESN, 'good morning' transaction, etc.)

If applicable, resources necessary to operate in an intersystem communication (ISC) environment (i.e., LU6.1, LU6.2, and MRO)

Use the ACF2 ACFRPTRX or ACFRPTXR reports to verify if the CICS default userid has access to any resources or datasets."
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for ACF2'
  tag check_id: 'C-25983r868099_chk'
  tag severity: 'medium'
  tag gid: 'V-224306'
  tag rid: 'SV-224306r868101_rule'
  tag stig_id: 'ZCIC0041'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-25971r868100_fix'
  tag 'documentable'
  tag legacy: ['SV-7523', 'V-7119']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
