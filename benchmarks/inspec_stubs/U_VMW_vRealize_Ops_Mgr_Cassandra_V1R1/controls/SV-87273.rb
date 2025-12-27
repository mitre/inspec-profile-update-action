control 'SV-87273' do
  title 'The Cassandra database log configuration file must be protected from unauthorized read access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access. 

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records. 

If an attacker were to gain access to audit tools, he could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.'
  desc 'check', 'Review the Cassandra Server settings to ensure the log configuration file is protected from unauthorized read access.

At the command prompt, execute the following command:

# ls -l /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml

If the file does not have permissions of "0640", this is a finding.'
  desc 'fix', 'Configure the Cassandra Server log configuration file to be protected from unauthorized read access.

At the command prompt, execute the following command:

# chmod 0640 /usr/lib/vmware-vcops/user/conf/cassandra/logback.xml'
  impact 0.5
  ref 'DPMS Target VMware Cassandra'
  tag check_id: 'C-72797r1_chk'
  tag severity: 'medium'
  tag gid: 'V-72641'
  tag rid: 'SV-87273r1_rule'
  tag stig_id: 'VROM-CS-000080'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag fix_id: 'F-79045r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
