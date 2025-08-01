control 'SV-87289' do
  title 'The Cassandra Server must uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'Review the Cassandra Server configuration to ensure organizational users are uniquely identified and authenticated when logging on/connecting to the system.

Open "cqlsh" prompt in the Cassandra Server and type in "LIST USERS;" command. Review the list of accounts available against product documentation and determine if any shared accounts exist.

If accounts are determined to be shared, determine if individuals are first individually authenticated.

If individuals are not individually authenticated before using the shared account, this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to uniquely identify and authenticate all organizational users who log on/connect to the system.

Create identity-based account for all the users accessing database (CREATE USER IF NOT EXISTS <identity based username> WITH PASSWORD <password>)

Build/configure applications to ensure successful individual authentication prior to shared account access.'
  impact 0.7
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72813r1_chk'
  tag severity: 'high'
  tag gid: 'V-72657'
  tag rid: 'SV-87289r1_rule'
  tag stig_id: 'VROM-CS-000130'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-79061r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
