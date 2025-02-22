control 'SV-259108' do
  title 'The vCenter UI service must protect logs from unauthorized access.'
  desc 'Log data is essential in the investigation of events. The accuracy of the information is always pertinent. One of the first steps an attacker will take is the modification or deletion of log records to cover tracks and prolong discovery. The web server must protect the log data from unauthorized modification.

'
  desc 'check', "At the command prompt, run the following command:

# find /var/log/vmware/vsphere-ui/ -xdev -type f -a '(' -perm -o+w -o -not -user vsphere-ui -o -not -group users -a -not -group root ')' -exec ls -ld {} \\;

If any files are returned, this is a finding."
  desc 'fix', 'At the command prompt, run the following commands:

# chmod o-w <file>
# chown vsphere-ui:users <file>

Note: Substitute <file> with the listed file.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA User Interface (UI)'
  tag check_id: 'C-62848r935226_chk'
  tag severity: 'medium'
  tag gid: 'V-259108'
  tag rid: 'SV-259108r935228_rule'
  tag stig_id: 'VCUI-80-000025'
  tag gtitle: 'SRG-APP-000118-AS-000078'
  tag fix_id: 'F-62757r935227_fix'
  tag satisfies: ['SRG-APP-000118-AS-000078', 'SRG-APP-000119-AS-000079', 'SRG-APP-000120-AS-000080']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9 a', 'AU-9 a', 'AU-9 a']
end
