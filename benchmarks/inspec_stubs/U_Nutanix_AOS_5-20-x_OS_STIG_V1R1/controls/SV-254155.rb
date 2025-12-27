control 'SV-254155' do
  title 'Nutanix AOS must generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Confirm Nutanix AOS generates audit records when concurrent logons to the same account occur.

$ sudo  grep -i /var/run/faillock /etc/audit/audit.rules
-w /var/run/faillock -p wa -k logins

$ sudo grep -i /var/log/lastlog /etc/audit/audit.rules
-w /var/log/lastlog -p wa -k logins 

If the commands listed do not return any output, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57640r846551_chk'
  tag severity: 'medium'
  tag gid: 'V-254155'
  tag rid: 'SV-254155r846553_rule'
  tag stig_id: 'NUTX-OS-000510'
  tag gtitle: 'SRG-OS-000470-GPOS-00214'
  tag fix_id: 'F-57591r846552_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
