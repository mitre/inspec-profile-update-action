control 'SV-100975' do
  title 'Lighttpd must have the correct group-ownership on the log files to ensure they are protected from unauthorized modification.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

Lighttpd creates its own logs. It does not use an external log system. The Lighttpd log must be protected from unauthorized modification.'
  desc 'check', 'At the command prompt, execute the following command:

ls -l /opt/vmware/var/log/lighttpd/*.log

If the group-owner is not "root", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chown root:root /opt/vmware/var/log/lighttpd/*.log'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-90019r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90325'
  tag rid: 'SV-100975r1_rule'
  tag stig_id: 'VRAU-LI-000115'
  tag gtitle: 'SRG-APP-000119-WSR-000069'
  tag fix_id: 'F-97067r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000163']
  tag nist: ['AU-9 a']
end
