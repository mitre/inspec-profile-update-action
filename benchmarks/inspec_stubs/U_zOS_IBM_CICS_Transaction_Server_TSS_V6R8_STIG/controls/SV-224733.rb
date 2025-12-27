control 'SV-224733' do
  title 'CICS default logonid(s) must be defined and/or controlled in accordance with the security requirements.'
  desc 'CICS is a transaction-processing product that provides programmers with the facilities to develop interactive applications. Improperly defined or controlled CICS userids (i.e., region, default, and terminal users) may provide an exposure and vulnerability within the CICS environment. This could result in the compromise of the confidentiality, integrity, and availability of the CICS region, applications, and customer data.'
  desc 'check', "Refer to the following report produced by the z/OS Data Collection:

- EXAM.RPT(CICSPROC)

Refer to the following report produced by the TSS Data Collection and Data Set and Resource Data Collection:

- TSSCMDS.RPT(@ACIDS)
- SENSITVE.RPT(WHOHOTRA)

Refer to the information gathered from the CICS Systems Programmer's Worksheet filled out from previous vulnerability ZCIC0010.

Ensure the following items are in effect for the CICS default ACID (i.e., DFLTUSER=default userid). If all of the following guidance is true, this is not a finding.

1) Not granted the TSS BYPASS privilege.
2) No access to interactive on-line facilities (e.g., TSO) other than CICS.
3) OPTIME parameter is set to 15 minutes.

4) A system's default time for terminal lock-out or session termination may be lengthened to 30 minutes at the discretion of the ISSM. The ISSM will maintain the documentation for each system with a time-out adjusted beyond the 15-minute recommendation to explain the basis for this decision.

5) Restricted from accessing all data sets and resources with the following exceptions:

(a) Non-restricted CICS transactions (e.g., CESF, CESN, 'good morning' transaction, etc.).
(b) If applicable, resources necessary to operate in an intersystem communication (ISC) environment (i.e., LU6.1, LU6.2, and MRO)."
  desc 'fix', "Review all CICS region, default, and end-user userids to ensure they are defined and controlled as required.

Ensure the following items are in effect for the CICS default ACID (i.e., DFLTUSER=default userid): 

1) Not granted the TSS BYPASS privilege. 

2) No access to interactive on-line facilities (e.g., TSO) other than CICS. 

3) OPTIME parameter is set to 15 minutes. can be increased  up to 30 if justified by the ISSM.

4) Restricted from accessing all data sets and resources with the following exceptions: 

  (a) Non-restricted CICS transactions (e.g., CESF, 
       CESN, 'good morning' transaction, etc.). 

  (b) If applicable, resources necessary to operate in an 
       intersystem communication (ISC) environment (i.e., 
       LU6.1, LU6.2, and MRO)."
  impact 0.5
  ref 'DPMS Target zOS IBM CICS Transaction Server for TSS'
  tag check_id: 'C-26424r868632_chk'
  tag severity: 'medium'
  tag gid: 'V-224733'
  tag rid: 'SV-224733r868634_rule'
  tag stig_id: 'ZCIC0041'
  tag gtitle: 'SRG-OS-000104'
  tag fix_id: 'F-26412r868633_fix'
  tag 'documentable'
  tag legacy: ['SV-7537', 'V-7119']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
