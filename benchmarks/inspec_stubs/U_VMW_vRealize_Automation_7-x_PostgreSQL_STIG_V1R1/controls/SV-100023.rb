control 'SV-100023' do
  title 'The vRA PostgreSQL database must use md5 for authentication.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to the DBMS.'
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
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89065r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89373'
  tag rid: 'SV-100023r1_rule'
  tag stig_id: 'VRAU-PG-000165'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-96115r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
