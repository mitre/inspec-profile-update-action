control 'SV-54247' do
  title 'Web server log files must only be accessible by privileged users.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by non-privileged users.'
  desc 'check', 'Review the web server documentation and deployed configuration settings to determine if the web server logging features protect log information from unauthorized access.

Review file system settings to verify the log files have secure file permissions.

If the web server log files are not protected from unauthorized access, this is a finding.'
  desc 'fix', 'Configure the web server log files so unauthorized access of log information is not possible.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-48067r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41670'
  tag rid: 'SV-54247r3_rule'
  tag stig_id: 'SRG-APP-000118-WSR-000068'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-47129r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
