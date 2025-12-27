control 'SV-240297' do
  title 'The vRA PostgreSQL database must be limited to authorized accounts.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 

(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'At the command prompt, execute the following command to enter the psql prompt:

# cat /storage/db/pgdata/pg_hba.conf

If any rows have "trust" specified for the "METHOD" column, this is a finding.'
  desc 'fix', 'Navigate to and open /storage/db/pgdata/pg_hba.conf.  

Navigate to the user that has a method of "trust".  

Change the method to "md5".

A correct, typical line will look like the following:
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host       all                        all                 127.0.0.1/32           md5'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x PostgreSQL'
  tag check_id: 'C-43530r668733_chk'
  tag severity: 'medium'
  tag gid: 'V-240297'
  tag rid: 'SV-240297r879589_rule'
  tag stig_id: 'VRAU-PG-000160'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-43489r668734_fix'
  tag 'documentable'
  tag legacy: ['SV-100021', 'V-89371']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
