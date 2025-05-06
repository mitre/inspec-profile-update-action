control 'SV-224497' do
  title 'CICS logonid(s) must have time-out limit set to 15 minutes.'
  desc 'CICS is a transaction-processing product that provides programmers with the facilities to develop interactive applications. Improperly defined or controlled CICS region userids may provide an exposure and vulnerability within the CICS environment.  This could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.

RACF provides the PROPCNTL class to prevent userids such as the CICS region userid from being propogated/used by unauthorized userids.'
  desc 'check', 'a)	Refer to the following report produced by the RACF Data Collection:

-	RACFCMDS.RPT(LISTUSER)

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

NOTE: Any userid that does not have a TIMEOUT parameter specified will obtain its TIMEOUT parameter from the default value set in ZCIC0041. Any userid that specifies a TIMEOUT parameter must meet the requirements specified below.

b)	Ensure that all userids with a CICS segment have the TIMEOUT parameter set to 15 minutes.

c)	If (b) is true for each CICS region and/or CICS user, there is NO FINDING.

NOTE:	If the time-out limit is greater than 15 minutes, and the system is processing unclassified information, review the following items.  If any of these is true, there is NO FINDING.

1)	If a session is not terminated, but instead is locked out after 15 minutes of inactivity, a process must be in place that requires user identification and authentication before the session is unlocked.  Session lock-out will be implemented through system controls or terminal screen protection.
2)	A system’s default time for terminal lock-out or session termination may be lengthened to 30 minutes at the discretion of the IAM.  The IAM will maintain the documentation for each system with a time-out adjusted beyond the 15-minute recommendation to explain the basis for this decision.
3)	The IAM may set selected userids to have a time-out of up to 60 minutes in order to complete critical reports or transactions without timing out.  Each exception must meet the following criteria:

(a)	The time-out exception cannot exceed 60 minutes.
(b)	A letter of justification fully documenting the user requirement(s) must be submitted and approved by the site IAM.  In addition, this letter must identify an alternate means of access control for the terminal(s) involved (e.g., a room that is locked at all times, a room with a cipher lock to limit access, a password protected screen saver set to 30 minutes or less, etc.).
(c)	The requirement must be revalidated on an annual basis.

 
c)	If the CICS time-out limit is not specified for 15 minutes of inactivity, and the previously mentioned exceptions do not apply, this is a FINDING.'
  desc 'fix', 'Review all CICS region, default, and end-user userids to ensure they are defined and controlled as required. 

Ensure that all userids with a CICS segment have the TIMEOUT parameter set to 15 minutes.

Examples: Use the RACF ALtUser command to assign the required value:

ALU <cics user> CICS(TIMEOUT(15))'
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for RACF'
  tag check_id: 'C-26180r520277_chk'
  tag severity: 'medium'
  tag gid: 'V-224497'
  tag rid: 'SV-224497r520279_rule'
  tag stig_id: 'ZCIC0042'
  tag gtitle: 'SRG-OS-000029'
  tag fix_id: 'F-26168r520278_fix'
  tag 'documentable'
  tag legacy: ['SV-7540', 'V-7120']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
