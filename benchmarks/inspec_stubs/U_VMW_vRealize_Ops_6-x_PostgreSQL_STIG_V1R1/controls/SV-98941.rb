control 'SV-98941' do
  title 'The vROps PostgreSQL DB must enforce access restrictions associated with changes to the configuration of the DBMS or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'At the command prompt, enter the following command:

# ls -l /storage/db/vcops/vpostgres/data/*conf* /var/vmware/vpostgres/9.3/.pgpass

If the permissions on any of the listed files are not "600", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

# chmod 600 <file>

Note: Replace <file> with the file with incorrect permissions.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-87983r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88291'
  tag rid: 'SV-98941r1_rule'
  tag stig_id: 'VROM-PG-000395'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-95033r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
