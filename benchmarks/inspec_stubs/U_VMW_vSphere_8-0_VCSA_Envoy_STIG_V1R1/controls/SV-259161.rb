control 'SV-259161' do
  title 'The vCenter Envoy and Rhttpproxy service log files permissions must be set correctly.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve. In addition, access to log records provides information an attacker could potentially use to their advantage since each event record might contain communication ports, protocols, services, trust relationships, usernames, etc.

The web server must protect the log data from unauthorized read, write, copy, etc. This can be done by the web server if the web server is also doing the logging function. The web server may also use an external log system. In either case, the logs must be protected from access by nonprivileged users.

'
  desc 'check', "At the command prompt, run the following commands:

# find /var/log/vmware/rhttpproxy/ -xdev -type f -a '(' -perm -o+w -o -not -user rhttpproxy -o -not -group rhttpproxy ')' -exec ls -ld {} \\;
# find /var/log/vmware/envoy/ -xdev -type f -a '(' -perm -o+w -o -not -user envoy -o -not -group envoy ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', 'At the command prompt, run the following commands for rhttpproxy log files:

# chmod o-w <file>
# chown rhttpproxy:rhttpproxy <file>

or

At the command prompt, run the following commands for envoy log files:

# chmod o-w <file>
# chown envoy:envoy <file>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Envoy'
  tag check_id: 'C-62901r935385_chk'
  tag severity: 'medium'
  tag gid: 'V-259161'
  tag rid: 'SV-259161r935387_rule'
  tag stig_id: 'VCRP-80-000019'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-62810r935386_fix'
  tag satisfies: ['SRG-APP-000118-WSR-000068', 'SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
