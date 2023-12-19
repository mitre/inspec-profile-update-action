control 'SV-254153' do
  title 'Nutanix AOS must generate audit records when successful/unsuccessful attempts to modify categories of information occur.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Confirm Nutanix AOS generates audit records for successful/unsuccessful attempts to modify categories of information.

$ sudo grep -i /usr/sbin/semanage /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=4294967295 -k secobjects

$ sudo grep -i /usr/sbin/setsebool /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=4294967295 -k secobjects

$ sudo grep -i /usr/bin/chcon /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k secobjects

$ sudo grep -iw /usr/sbin/setfiles /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

If the commands does not return any output, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57638r846545_chk'
  tag severity: 'medium'
  tag gid: 'V-254153'
  tag rid: 'SV-254153r846547_rule'
  tag stig_id: 'NUTX-OS-000470'
  tag gtitle: 'SRG-OS-000465-GPOS-00209'
  tag fix_id: 'F-57589r846546_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
