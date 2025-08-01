control 'SV-254164' do
  title 'Nutanix AOS must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what type of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.'
  desc 'check', 'Verify Nutanix AOS generates audit records when successful/unsuccessful attempts to use the following commands occur.

Check that the following system call is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo auditctl -l | grep -iw /usr/bin/su /etc/audit/audit.rules
If the output is not -a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged, this is a finding.

$ sudo auditctl -l | grep -iw /usr/bin/sudo /etc/audit/audit.rules
If the output is not -a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged, this is a finding.

$ sudo grep -i "/etc/sudoers" /etc/audit/audit.rules
If the output is not -w /etc/sudoers -p wa -k actions, this is a finding.

$ sudo grep -i "/etc/sudoers.d/" /etc/audit/audit.rules
If the output is not -w /etc/sudoers.d/ -p wa -k actions, this is a finding.

$ sudo grep -i /usr/bin/newgrp /etc/audit/audit.rules
If the output is not -a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged, this is a finding.

$ sudo grep -i /usr/bin/chsh /etc/audit/audit.rules
If the output is not -a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57649r846578_chk'
  tag severity: 'medium'
  tag gid: 'V-254164'
  tag rid: 'SV-254164r846580_rule'
  tag stig_id: 'NUTX-OS-000620'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag fix_id: 'F-57600r846579_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
