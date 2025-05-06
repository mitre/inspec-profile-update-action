control 'SV-240776' do
  title 'tc Server VCAC log files must be protected from unauthorized modification.'
  desc 'Log data is essential in the investigation of events. The accuracy of the information is always pertinent. Information that is not accurate does not help in the revealing of potential security risks and may hinder the early discovery of a system compromise. One of the first steps an attacker will undertake is the modification or deletion of log records to cover his tracks and prolong discovery.

The web server must protect the log data from unauthorized modification. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from modification by non-privileged users.'
  desc 'check', 'At the command prompt, execute the following command:

ls -lL /storage/log/vmware/vcac

If any log files are not owned by "root" or "vcac", this is a finding.'
  desc 'fix', 'At the command prompt, execute the following command:

Set the owner & group of these files: access_log.txt, audit.log, catalina.log, catalina.out, gc_logs.log.0.current, host-manager.log, localhost.log, manager.log, and tomcat.pid to vcac, with the following command:

chown vcac:vcac /storage/log/vmware/vcac/<file>

Set all other files not listed above to the owner and group of root, with the following command:

chown root:root /storage/log/vmware/vcac/<file>

Note: Substitute <file> with the listed file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44009r674070_chk'
  tag severity: 'medium'
  tag gid: 'V-240776'
  tag rid: 'SV-240776r879577_rule'
  tag stig_id: 'VRAU-TC-000285'
  tag gtitle: 'SRG-APP-000119-WSR-000069'
  tag fix_id: 'F-43968r674071_fix'
  tag 'documentable'
  tag legacy: ['SV-100637', 'V-89987']
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
