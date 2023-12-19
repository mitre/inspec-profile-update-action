control 'SV-224307' do
  title 'CICS logonid(s) must be configured with proper timeout and signon limits.'
  desc 'CICS is a transaction-processing product that provides programmers with the facilities to develop interactive applications. Improperly defined or controlled CICS userids (i.e., region, default, and terminal users) may provide an exposure and vulnerability within the CICS environment.  This could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', "a)       Refer to the following report produced by the ACF2 Data Collection:

-       ACF2CMDS.RPT(LOGONIDS)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

Note: Any logonid that does not have an IDLE value specified will obtain its IDLE value from the default value set in ZCIC0041. Any logonid that specifies an IDLE value must meet the requirements specified below.

b) For all logonids with the CICS attribute that have IDLE(15) specified this is not a finding.

NOTE: If the time-out limit is greater than 15 minutes, and the system is processing unclassified information, review the following items. If any of these is true, this is not a finding.

If a session is not terminated, but instead is locked out after 15 minutes of inactivity, a process must be in place that requires user identification and authentication before the session is unlocked. Session lock-out will be implemented through system controls or terminal screen protection.
A system's default time for terminal lock-out or session termination may be lengthened to 30 minutes at the discretion of the ISSM. The ISSM will maintain the documentation for each system with a time-out adjusted beyond the 15-minute recommendation to explain the basis for this decision.
The ISSM may set selected userids to have a time-out of up to 60 minutes in order to complete critical reports or transactions without timing out. Each exception must meet the following criteria:

        The time-out exception cannot exceed 60 minutes.
        A letter of justification fully documenting the user requirement(s) must be submitted and approved by the site IAM. In addition, this letter must identify an alternate means of access control for the terminal(s) involved (e.g., a room that is locked at all times, a room with a cipher lock to limit access, a password protected screen saver set to 30 minutes or less, etc.). The requirement must be revalidated on an annual basis.


c) If the MULTSIGN option in the  logonid record field is restricted to test or development use, this is not a finding."
  desc 'fix', 'Ensure that all userids with a CICS segment have the TIMEOUT parameter set to 15 minutes.
Ensure that all LIDs authorized to access a CICS facility restrict MULTSIGN to test and development use.

Examples:
SET LID
LIST CICS
CHANGE CICS IDLE(15)'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for ACF2'
  tag check_id: 'C-25984r520241_chk'
  tag severity: 'medium'
  tag gid: 'V-224307'
  tag rid: 'SV-224307r520243_rule'
  tag stig_id: 'ZCIC0042'
  tag gtitle: 'SRG-OS-000029'
  tag fix_id: 'F-25972r520242_fix'
  tag 'documentable'
  tag legacy: ['SV-7524', 'V-7120']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
