control 'SV-223496' do
  title 'ACF2 LOGONIDs must be defined with the required fields completed.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', "From an ACF Command Screen enter:
SET LID
LIST *

If the below listed fields are complete for all logonids, this is not a finding.

NAME User's name
UID-String All fields defined in the ACFFDR @UID macro

NOTE: A completed NAME field that can either be traced back to a current DD Form 2875 or a Vendor Requirement (example: A Started Task). 

NOTE: A user may be required to have more than one logonid but users must not share userids."
  desc 'fix', "Define every user to ACF2 with a unique userid. (ACF2 calls this a logonid.) To ACF2, a user is an individual, a started task, or a batch job.

Every user will be fully identified within ACF2. Complete the following fields for every logonid:

NAME - User's name
UID-String - All fields defined in the ACFFDR @UID macro

All fields that comprise the standard UID string will be filled out for each user as a logonid is added.

Example:
SET LID
INSERT logonid UID(uid string) NAME(user name)"
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25169r504588_chk'
  tag severity: 'medium'
  tag gid: 'V-223496'
  tag rid: 'SV-223496r533198_rule'
  tag stig_id: 'ACF2-ES-000780'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25157r504589_fix'
  tag 'documentable'
  tag legacy: ['V-97691', 'SV-106795']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
