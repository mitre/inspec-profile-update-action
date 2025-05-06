control 'SV-240231' do
  title 'Lighttpd must have the correct ownership on the log files to ensure they are protected from unauthorized deletion.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

Lighttpd creates its own logs. It does not use an external log system. The Lighttpd log must be protected from unauthorized deletion.'
  desc 'check', 'At the command prompt, execute the following command:

ls -l /opt/vmware/var/log/lighttpd/*.log

If the owner is not "root", this is a finding.'
  desc 'fix', 'At the command prompt, enter the following commands:

chown root:root /opt/vmware/var/log/lighttpd/*.log'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43464r667868_chk'
  tag severity: 'medium'
  tag gid: 'V-240231'
  tag rid: 'SV-240231r879578_rule'
  tag stig_id: 'VRAU-LI-000125'
  tag gtitle: 'SRG-APP-000120-WSR-000070'
  tag fix_id: 'F-43423r667869_fix'
  tag 'documentable'
  tag legacy: ['SV-99899', 'V-89249']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
