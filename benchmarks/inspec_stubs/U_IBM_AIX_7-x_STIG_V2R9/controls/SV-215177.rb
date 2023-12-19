control 'SV-215177' do
  title 'The AIX SYSTEM attribute must not be set to NONE for any account.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Examine the "SYSTEM" attribute values for all users in the "/etc/security/user" file by running the following command: 
# lsuser -a SYSTEM ALL

The above command should yield the following output:
root SYSTEM=compat
daemon SYSTEM=compat
bin SYSTEM=compat
sys SYSTEM=compat

If the command displays SYSTEM=NONE for a user, this is a finding.'
  desc 'fix', 'For every user who has "SYSTEM=NONE", run the following command to set their "SYSTEM" value to "compat":

# chuser SYSTEM=compat [user_name]'
  impact 0.7
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16375r293982_chk'
  tag severity: 'high'
  tag gid: 'V-215177'
  tag rid: 'SV-215177r508663_rule'
  tag stig_id: 'AIX7-00-001010'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-16373r293983_fix'
  tag 'documentable'
  tag legacy: ['V-91425', 'SV-101523']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
