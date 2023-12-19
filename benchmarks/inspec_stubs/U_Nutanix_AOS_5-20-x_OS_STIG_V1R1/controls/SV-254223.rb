control 'SV-254223' do
  title 'Nutanix AOS must audit all activities performed during nonlocal maintenance and diagnostic sessions.'
  desc 'If events associated with nonlocal administrative access or diagnostic sessions are not logged, a major tool for assessing and investigating attacks would not be available.

This requirement addresses auditing-related issues associated with maintenance tools used specifically for diagnostic and repair actions on organizational information systems.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

This requirement applies to hardware/software diagnostic test equipment or tools. This requirement does not cover hardware/software components that may support information system maintenance, yet are a part of the system, for example, the software implementing "ping," "ls," "ipconfig," or the hardware and software implementing the monitoring port of an Ethernet switch.'
  desc 'check', 'Confirm Nutanix AOS audits all required activities performed during nonlocal maintenance and diagnostic sessions.

$ sudo grep -i /usr/sbin/semanage /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=4294967295 -k secobjects

$ sudo grep -i /usr/sbin/setsebool /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=4294967295 -k secobjects

$ sudo grep -i /usr/bin/chcon /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -k secobjects

$ sudo grep -iw /usr/sbin/setfiles /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/setfiles -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change

$ sudo grep -i /var/run/faillock /etc/audit/audit.rules
-w /var/run/faillock/ -p wa -k logins

$ sudo grep -i /var/log/lastlog /etc/audit/audit.rules
-w /var/log/lastlog -p wa -k logins

If any of the commands listed do not return any output, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS to audit all required activities performed during nonlocal maintenance and diagnostic sessions by running the following command.

salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57708r846755_chk'
  tag severity: 'medium'
  tag gid: 'V-254223'
  tag rid: 'SV-254223r846757_rule'
  tag stig_id: 'NUTX-OS-001390'
  tag gtitle: 'SRG-OS-000392-GPOS-00172'
  tag fix_id: 'F-57659r846756_fix'
  tag 'documentable'
  tag cci: ['CCI-002884']
  tag nist: ['MA-4 (1) (a)']
end
