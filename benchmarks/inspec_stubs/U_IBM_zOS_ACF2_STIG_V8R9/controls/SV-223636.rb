control 'SV-223636' do
  title 'IBM z/OS UNIX groups must be defined with a unique GID.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'From an ACF Command screen enter:
SET PROFILE(GROUP) DIVISION(OMVS)
LIST LIKE(-)

If each of the definitions have a unique GID, this is not a finding.'
  desc 'fix', 'Define each UNIX group with a unique GID.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25309r501045_chk'
  tag severity: 'medium'
  tag gid: 'V-223636'
  tag rid: 'SV-223636r533198_rule'
  tag stig_id: 'ACF2-US-000210'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25297r501046_fix'
  tag 'documentable'
  tag legacy: ['SV-107081', 'V-97977']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
