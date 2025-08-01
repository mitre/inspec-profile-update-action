control 'SV-258975' do
  title 'The vCenter STS service logs folder permissions must be set correctly.'
  desc 'Log data is essential in the investigation of events. The accuracy of the information is always pertinent. One of the first steps an attacker will take is the modification or deletion of log records to cover tracks and prolong discovery. The web server must protect the log data from unauthorized modification.

'
  desc 'check', "At the command prompt, run the following command:

# find /var/log/vmware/sso/ -xdev ! -name lookupsvc-init.log ! -name sts-prestart.log -type f -a '(' -perm -o+w -o -not -user sts -o -not -group lwis ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', 'At the command prompt, run the following commands:

# chmod o-w <file>
# chown sts:lwis <file>

Note: Substitute <file> with the listed file.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Secure Token Service (STS)'
  tag check_id: 'C-62715r934581_chk'
  tag severity: 'medium'
  tag gid: 'V-258975'
  tag rid: 'SV-258975r934583_rule'
  tag stig_id: 'VCST-80-000025'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag fix_id: 'F-62624r934582_fix'
  tag satisfies: ['SRG-APP-000118-AS-000078', 'SRG-APP-000119-AS-000079', 'SRG-APP-000120-AS-000080']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
