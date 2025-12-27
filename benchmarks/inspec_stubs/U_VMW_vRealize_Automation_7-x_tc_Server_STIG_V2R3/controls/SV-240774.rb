control 'SV-240774' do
  title 'tc Server HORIZON log files must be protected from unauthorized modification.'
  desc 'Log data is essential in the investigation of events. The accuracy of the information is always pertinent. Information that is not accurate does not help in the revealing of potential security risks and may hinder the early discovery of a system compromise. One of the first steps an attacker will undertake is the modification or deletion of log records to cover his tracks and prolong discovery.

The web server must protect the log data from unauthorized modification. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from modification by non-privileged users.'
  desc 'check', 'At the command prompt, execute the following command:

ls -lL /storage/log/vmware/vcac

If any log files are not owned by "root" or "vcac", this is a finding.

The following files should be owned by "vcac":
access_log
catalina.out
gc_logs
host-manager
localhost
manager
tc Server.pid

The following files should be owned by "root":
system-config-history
telemetry
toolsgc
vcac-config'
  desc 'fix', 'At the command prompt, execute the following command:

chown <owner>:<owner> /storage/log/vmware/vcac/<file>

Note: Substitute <file> with the listed file.

Note: Substitute <owner> with the correct value below.

The following files should be owned by "vcac":
access_log
catalina.out
gc_logs
host-manager
localhost
manager
tc Server.pid

The following files should be owned by "root":
system-config-history
telemetry
toolsgc
vcac-config'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44007r674423_chk'
  tag severity: 'medium'
  tag gid: 'V-240774'
  tag rid: 'SV-240774r879577_rule'
  tag stig_id: 'VRAU-TC-000275'
  tag gtitle: 'SRG-APP-000119-WSR-000069'
  tag fix_id: 'F-43966r674065_fix'
  tag 'documentable'
  tag legacy: ['SV-100633', 'V-89983']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
