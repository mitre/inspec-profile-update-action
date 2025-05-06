control 'SV-87311' do
  title 'The Cassandra database must protect the truststore file.'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Review the Cassandra Server configuration to ensure the truststore file is protected.

At the command prompt, execute the following command:

# ls -l /storage/vcops/user/conf/ssl/tcserver.truststore

If the file permissions are not "0640", this is a finding.'
  desc 'fix', 'Configure the Cassandra Server to protect the truststore file.

At the command line execute the following command:

# chmod 0640 /storage/vcops/user/conf/ssl/tcserver.truststore'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72835r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72679'
  tag rid: 'SV-87311r1_rule'
  tag stig_id: 'VROM-CS-000235'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-79083r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
