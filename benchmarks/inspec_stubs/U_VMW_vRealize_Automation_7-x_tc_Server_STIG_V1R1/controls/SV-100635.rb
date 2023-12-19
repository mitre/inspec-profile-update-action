control 'SV-100635' do
  title 'tc Server VCO log files must be protected from unauthorized modification.'
  desc 'Log data is essential in the investigation of events. The accuracy of the information is always pertinent. Information that is not accurate does not help in the revealing of potential security risks and may hinder the early discovery of a system compromise. One of the first steps an attacker will undertake is the modification or deletion of log records to cover his tracks and prolong discovery.

The web server must protect the log data from unauthorized modification. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from modification by non-privileged users.'
  desc 'check', 'At the command prompt, execute the following command:

ls -lL /storage/log/vmware/vco/app-server

If any log files are not owned by "vco", this is a finding.'
  desc 'fix', 'At the command prompt, execute the following command:

chown vco:vco /storage/log/vmware/vco/app-server/<file>

Note: Substitute <file> with the listed file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89677r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89985'
  tag rid: 'SV-100635r1_rule'
  tag stig_id: 'VRAU-TC-000280'
  tag gtitle: 'SRG-APP-000119-WSR-000069'
  tag fix_id: 'F-96727r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
