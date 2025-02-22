control 'SV-87275' do
  title 'The Cassandra database log configuration file must have the correct owner.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the modification of audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Review the Cassandra Server settings to ensure the log configuration file has the correct owner.

At the command prompt, execute the following command:

# ls -l /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If the file is not owned by "admin", this is a finding.'
  desc 'fix', 'Configure the Cassandra Server log configuration file to have the correct owner.

At the command prompt, execute the following command:

# chown admin /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72799r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72643'
  tag rid: 'SV-87275r1_rule'
  tag stig_id: 'VROM-CS-000085'
  tag gtitle: 'SRG-APP-000122-DB-000203'
  tag fix_id: 'F-79047r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
