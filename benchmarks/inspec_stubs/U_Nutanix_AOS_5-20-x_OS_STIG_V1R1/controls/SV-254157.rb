control 'SV-254157' do
  title 'Nutanix AOS must generate audit records for privileged account activities.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Confirm Nutanix AOS generates audit records for privileged activities or other system-level access.

$ sudo grep -w chage /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w newgrp /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -i /usr/bin/chsh /etc/audit/audit.rules
-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w "userhelper" /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-passwd

$ sudo grep -w "unix_chkpwd" /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

$ sudo grep -w faillock /etc/audit/audit.rules
-w /var/run/faillock/ -p wa -k logins

$ sudo grep -w lastlog /etc/audit/audit.rules
-w /var/log/lastlog -p wa -k logins

$ sudo grep -iw "/usr/sbin/pam_timestamp_check" /etc/audit/audit.rules
-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

If the privileged activities access listed do not return any output, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command.

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57642r846557_chk'
  tag severity: 'medium'
  tag gid: 'V-254157'
  tag rid: 'SV-254157r846559_rule'
  tag stig_id: 'NUTX-OS-000530'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-57593r846558_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
