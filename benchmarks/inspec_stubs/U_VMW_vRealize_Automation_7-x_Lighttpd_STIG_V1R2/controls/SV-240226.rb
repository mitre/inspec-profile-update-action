control 'SV-240226' do
  title 'Lighttpd must have the correct group-ownership on the log files to ensure they are only be accessible by privileged users.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

Lighttpd creates its own logs. It does not use an external log system. The Lighttpd log must only be accessible by privileged users.'
  desc 'check', 'At the command prompt, execute the following command:

ls -l /opt/vmware/var/log/lighttpd/*.log

If the group-owner is not "root", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chown root:root /opt/vmware/var/log/lighttpd/*.log'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43459r667853_chk'
  tag severity: 'medium'
  tag gid: 'V-240226'
  tag rid: 'SV-240226r879576_rule'
  tag stig_id: 'VRAU-LI-000100'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-43418r667854_fix'
  tag 'documentable'
  tag legacy: ['SV-99893', 'V-89243']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
