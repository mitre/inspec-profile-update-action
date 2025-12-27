control 'SV-224496' do
  title 'CICS default logonid(s) must be defined and/or controlled in accordance with the security requirements.'
  desc 'CICS is a transaction-processing product that provides programmers with the facilities to develop interactive applications. An improperly defined or controlled CICS default userid may provide an exposure and vulnerability within the CICS environment. This could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', "a) Refer to the following report produced by the z/OS Data Collection:

- EXAM.RPT(CICSPROC)

Refer to the following reports produced by the RACF Data Collection:

- RACFCMDS.RPT(LISTUSER)
- SENSITVE.RPT(TCICSTRN)
- SENSITVE.RPT(GCICSTRN)

NOTE: If a CICS region is using a site-defined transaction resource class pair, execute a RACF RLIST command against these resource classes.

Refer to the CICS Systems Programmer Worksheets filled out from previous vulnerability ZCIC0010.

b) Ensure the following items are in effect for the CICS default userid (i.e., DFLTUSER=default userid):

1) Not granted the RACF OPERATIONS attribute.
2) No access to interactive on-line facilities (e.g., TSO) other than CICS.
3) TIMEOUT parameter in the CICS segment is set to 15 minutes.

4) A system's default time for terminal lock-out or session termination may be lengthened to 30 minutes at the discretion of the ISSM. The ISSM will maintain the documentation for each system with a time-out adjusted beyond the 15-minute recommendation to explain the basis for this decision.

5) Restricted from accessing all data sets and resources with the following exceptions:

(a) Non-restricted CICS transactions (e.g., CESF, CESN, 'good morning' transaction, etc.)
(b) If applicable, resources necessary to operate in an intersystem communication (ISC) environment (i.e., LU6.1, LU6.2, and MRO)

Note: Refer to the IBM CICS Transaction Server Resource Definition Guide for latest and most accurate definition for the Default CICS User. 
Note: Any exceptions to these guidelines must be approved by the site ISSO and documented in site security plan.

NOTE: Execute the JCL in CNTL(IRRUT100) using the CICS default userid as SYSIN input. This report lists all occurrences of this userid within the RACF database, including data set and resource access lists.

c) If all items in (b) are true, this not a finding.

d) If any item in (b) is untrue, this is a finding."
  desc 'fix', "Ensure the following items are in effect for the CICS default userid (i.e., DFLTUSER=default userid):

1) Not granted the RACF OPERATIONS attribute.

a) Issue a RACF LU (Listuser) command on the CICS default userid.

b) The OPERATIONS attribute can be removed via the RACF command ALU <cicsdefaultuser> NOOPERATIONS

2) No access to interactive on-line facilities (e.g., TSO) other than CICS.

a) Use the RACF ALU (Altuser) command to remove attributes such as TSO. Example: ALU <cicsdefaultuser> NOTSO

3) TIMEOUT parameter in the CICS segment is set to 15 minutes.

4) A system's default time for terminal lock-out or session termination may be lengthened to 30 minutes at the discretion of the ISSM. The ISSM will maintain the documentation for each system with a time-out adjusted beyond the 15-minute recommendation to explain the basis for this decision.

a) Use the RACF LU (ListUser) command to display the CICS segment. An example is shown here: 
LU <cicsdefaultuser> CICS

b) Use the RACF ALU command to set the 15 minute timeout value. An example is shown here: 
ALU <cicsdefaultuser> CICS(TIMEOUT(15))

5) Restricted from accessing all data sets and resources with the following exceptions:

a) Delete the CICS default user from dataset access lists via the command:
PE '<dataset profile name>' ID(<cicsdefaultuser>) DEL

(a) Non-restricted CICS transactions (e.g., CESF, CESN, 'good morning' transaction, etc.)

(b) If applicable, resources necessary to operate in an intersystem communication (ISC) environment (i.e., LU6.1, LU6.2, and MRO)

NOTE: Execute the JCL in CNTL(IRRUT100) using the CICS default userid as SYSIN input. This report lists all occurrences of this userid within the RACF database, including data set and resource access lists.

c) If all items in (b) are true, there is no finding.

d) If any item in (b) is untrue, this is a finding."
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for RACF'
  tag check_id: 'C-26179r904395_chk'
  tag severity: 'medium'
  tag gid: 'V-224496'
  tag rid: 'SV-224496r904396_rule'
  tag stig_id: 'ZCIC0041'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26167r868327_fix'
  tag 'documentable'
  tag legacy: ['SV-7536', 'V-7119']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
