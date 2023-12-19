control 'SV-256712' do
  title 'Lookup Service log files must only be accessible by privileged users.'
  desc 'Log data is essential in the investigation of events. If log data were to become compromised, competent forensic analysis and discovery of the true source of potentially malicious system activity would be difficult, if not impossible, to achieve.

In addition, access to log records provides information an attacker could use to their advantage because each event record might contain communication ports, protocols, services, trust relationships, usernames, etc. The Lookup Service restricts all access to log files by default, but this configuration must be verified.

'
  desc 'check', "At the command prompt, run the following command:

# find /var/log/vmware/lookupsvc -xdev -type f -a '(' -perm /137 -o -not -user root -o -not -group root ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', 'At the command prompt, run the following commands:

# chmod 640 /var/log/vmware/lookupsvc/<file>
# chown root:root /var/log/vmware/lookupsvc/<file>

Note: Substitute <file> with the listed file.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 vCA Lookup Service'
  tag check_id: 'C-60387r888725_chk'
  tag severity: 'medium'
  tag gid: 'V-256712'
  tag rid: 'SV-256712r888727_rule'
  tag stig_id: 'VCLU-70-000007'
  tag gtitle: 'SRG-APP-000118-WSR-000068'
  tag fix_id: 'F-60330r888726_fix'
  tag satisfies: ['SRG-APP-000118-WSR-000068', 'SRG-APP-000119-WSR-000069', 'SRG-APP-000120-WSR-000070']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
