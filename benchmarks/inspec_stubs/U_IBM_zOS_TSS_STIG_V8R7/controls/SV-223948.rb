control 'SV-223948' do
  title 'Interactive ACIDs defined to CA-TSS must have the required fields completed.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS LIST (ACIDs) DATA (BASIC,TSO,CICS)

If all the fields and information listed below, are not present for all interactive users this is a finding.

FIELD DESCRIPTION VALUE
FACILITY Validated facilities to use BATCH, TSO, NCPASS, or other interactive Facility
PASSWORD logon password must have a value
INSTDATA Installation data optional
PROFILE Profile(s) optional
TSOLPROC Default TSO logon PROC optional for TSO users
TSOLACCT Default TSO logon account may be required for a fee for service.'
  desc 'fix', 'Review all interactive ACID definitions to ensure required information is provided. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes as required according to the following:

FIELD DESCRIPTION VALUE
FACILITY Validated facilities to use BATCH, TSO, NCPASS, or other interactive Facility
PASSWORD logon password must have a value
INSTDATA Installation data optional
PROFILE Profile(s) optional
TSOLPROC Default TSO logon PROC optional for TSO users
TSOLACCT Default TSO logon account may be required
for a fee for service.'
  impact 0.3
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25621r516243_chk'
  tag severity: 'low'
  tag gid: 'V-223948'
  tag rid: 'SV-223948r561402_rule'
  tag stig_id: 'TSS0-ES-000750'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25609r516244_fix'
  tag 'documentable'
  tag legacy: ['SV-107707', 'V-98603']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
