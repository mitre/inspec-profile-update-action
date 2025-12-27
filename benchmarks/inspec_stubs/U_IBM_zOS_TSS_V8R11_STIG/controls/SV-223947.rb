control 'SV-223947' do
  title 'The CA-TSS PASSWORD(NOPW) option must not be specified for any ACID type.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', "From the ISPF Command Shell enter:
TSS LIST(ACIDS) DATA(PASSWORD) - NOTE: To evaluate the PASSWORD option NOPW, it must be run under the MSCA's authority, if not the information will not be generated.

If PASSWORD(NOPW) is specified for any ACID types (USER, DCA, VCA, ZCA, LSCA, SCA, and MSCA), this is a finding."
  desc 'fix', 'Review definition of all ACID types (including USER, DCA, VCA, ZCA, LSCA, SCA, and MSCA) except for structure ACIDS such as: DEPARTMENT, DIVISION, ZONE, GROUP, and PROFILE to ensure that all ACIDs specify a password.

The following command is an example of how this can be corrected.

TSS REPLACE(user_ACID) PASSWORD(Text4Pwd,60'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25620r516240_chk'
  tag severity: 'high'
  tag gid: 'V-223947'
  tag rid: 'SV-223947r877788_rule'
  tag stig_id: 'TSS0-ES-000740'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25608r516241_fix'
  tag 'documentable'
  tag legacy: ['SV-107705', 'V-98601']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
