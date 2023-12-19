control 'SV-239788' do
  title 'The vROps PostgreSQL DB must protect its audit features from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. 

Depending upon the log format and application, system and application log tools may provide the only means to manipulate and manage application and system log data. It is, therefore, imperative that access to audit tools be controlled and protected from unauthorized access. 

Applications providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, OS-provided audit tools, vendor-provided audit tools, and open source audit tools needed to successfully view and manipulate audit information system activity and records. 

If an attacker were to gain access to audit tools, he could analyze audit logs for system weaknesses or weaknesses in the auditing itself. An attacker could also manipulate logs to hide evidence of malicious activity.'
  desc 'check', 'At the command prompt, enter the following command:

# ls -l /storage/db/vcops/vpostgres/data/*conf* /var/vmware/vpostgres/9.3/.pgpass

If the permissions on any of the listed files are not "600", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

# chmod 600 <file>

Note: Replace <file> with the file with incorrect permissions.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x PostgreSQL'
  tag check_id: 'C-43021r663739_chk'
  tag severity: 'medium'
  tag gid: 'V-239788'
  tag rid: 'SV-239788r879579_rule'
  tag stig_id: 'VROM-PG-000120'
  tag gtitle: 'SRG-APP-000121-DB-000202'
  tag fix_id: 'F-42980r663740_fix'
  tag 'documentable'
  tag legacy: ['SV-98899', 'V-88249']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
