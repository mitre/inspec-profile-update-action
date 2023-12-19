control 'SV-100045' do
  title 'The DBMS must enforce access restrictions associated with changes to the configuration of the DBMS or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'At the command prompt, enter the following command:

# ls -l /storage/db/pgdata/*conf*

If the permissions on any of the listed files are not "600", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

# chmod 600 <file>

Note: Replace <file> with the file with incorrect permissions.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x PostgreSQL'
  tag check_id: 'C-89087r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89395'
  tag rid: 'SV-100045r1_rule'
  tag stig_id: 'VRAU-PG-000310'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-96137r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
