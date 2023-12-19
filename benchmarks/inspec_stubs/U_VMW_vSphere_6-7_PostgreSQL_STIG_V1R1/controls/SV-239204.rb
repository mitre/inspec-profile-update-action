control 'SV-239204' do
  title 'VMware Postgres must require authentication on all connections.'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; 

(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts for detailed accountability of individual activity.

'
  desc 'check', 'At the command prompt, execute the following command:

# grep -v "^#" /storage/db/vpostgres/pg_hba.conf|grep -z --color=always "trust"

If any lines are returned, this is a finding.'
  desc 'fix', 'Navigate to and open /storage/db/pgdata/pg_hba.conf. 

Find and remove the line that has a method of "trust" in the far right column.

A correct, typical line will look like the following:
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host       all                        all                 127.0.0.1/32           md5'
  impact 0.7
  ref 'DPMS Target VMware vSphere 6.7 PostgreSQL'
  tag check_id: 'C-42437r678983_chk'
  tag severity: 'high'
  tag gid: 'V-239204'
  tag rid: 'SV-239204r678985_rule'
  tag stig_id: 'VCPG-67-000012'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-42396r678984_fix'
  tag satisfies: ['SRG-APP-000148-DB-000103', 'SRG-APP-000171-DB-000074']
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
