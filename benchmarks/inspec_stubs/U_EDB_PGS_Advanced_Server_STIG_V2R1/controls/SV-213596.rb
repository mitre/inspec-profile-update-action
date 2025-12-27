control 'SV-213596' do
  title 'The EDB Postgres Advanced Server must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Open "<postgresql data directory>/pg_hba.conf" in a viewer or editor.  (The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.)

If any rows have "trust" specified for the "METHOD" column, this is a finding.'
  desc 'fix', 'Open "<postgresql data directory>/pg_hba.conf" in an editor. (The default path for the postgresql data directory is /var/lib/ppas/9.5/data, but this will vary according to local circumstances.) 

If any rows have "trust" specified for the "METHOD" column, delete the rows or change them to other authentication methods.

Permitted methods in preferred order are:  peer (local only), cert, ldap, sspi, pam, md5'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14818r290100_chk'
  tag severity: 'medium'
  tag gid: 'V-213596'
  tag rid: 'SV-213596r508024_rule'
  tag stig_id: 'PPS9-00-004200'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-14816r290101_fix'
  tag 'documentable'
  tag legacy: ['SV-83695', 'V-69091']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
