control 'SV-256651' do
  title 'VAMI log files must only be accessible by privileged users.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve.

In addition, access to log records provides information an attacker could use to their advantage because each event record might contain communication ports, protocols, services, trust relationships, user names, etc.

'
  desc 'check', 'At the command prompt, run the following command:

# stat -c "%n has %a permissions and is owned by %U:%G" /opt/vmware/var/log/lighttpd/*.log

Expected result:

/opt/vmware/var/log/lighttpd/access.log has 644 permissions and is owned by root:root
/opt/vmware/var/log/lighttpd/error.log has 644 permissions and is owned by root:root

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'At the command prompt, run the following commands:

# chown root:root /opt/vmware/var/log/lighttpd/*.log
# chmod 644 /opt/vmware/var/log/lighttpd/*.log'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 VAMI STIG'
  tag check_id: 'C-60326r888473_chk'
  tag severity: 'medium'
  tag gid: 'V-256651'
  tag rid: 'SV-256651r888475_rule'
  tag stig_id: 'VCLD-70-000007'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-60269r888474_fix'
  tag satisfies: ['SRG-APP-000118-WSR-000068', 'SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
