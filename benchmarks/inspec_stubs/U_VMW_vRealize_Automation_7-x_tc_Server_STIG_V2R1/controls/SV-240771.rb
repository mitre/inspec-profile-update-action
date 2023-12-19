control 'SV-240771' do
  title 'tc Server HORIZON log files must only be accessible by privileged users.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by non-privileged users.'
  desc 'check', 'At the command prompt, execute the following command:

ls -lL /storage/log/vmware/horizon

If any log files have permissions less restrictive than "640", this is a finding.'
  desc 'fix', 'At the command prompt, execute the following commands:

chmod 640 /storage/log/vmware/horizon/<file>

sed -i "/^[^#]*UMASK/ c\\UMASK 077" /etc/login.defs

Note: Substitute <file> with the listed file.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44004r674055_chk'
  tag severity: 'medium'
  tag gid: 'V-240771'
  tag rid: 'SV-240771r674057_rule'
  tag stig_id: 'VRAU-TC-000260'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-43963r674056_fix'
  tag 'documentable'
  tag legacy: ['SV-100627', 'V-89977']
  tag cci: ['CCI-000162']
  tag nist: ['AU-9 a']
end
