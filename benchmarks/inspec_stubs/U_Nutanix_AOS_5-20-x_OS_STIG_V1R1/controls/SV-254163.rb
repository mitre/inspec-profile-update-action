control 'SV-254163' do
  title 'Nutanix AOS must initiate session audits at system start-up.'
  desc 'If auditing is enabled late in the start-up process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Determine if auditing is active by issuing the following command:

$ sudo systemctl is-active auditd.service
active

If the "auditd" status is not active, this is a finding.'
  desc 'fix', 'Configure the audit service to be active and start automatically with the system at startup. The Audit service is protected and restricted to allow access or modifications only from the root account.
$ sudo su -
# systemctl start auditd.service'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57648r846575_chk'
  tag severity: 'medium'
  tag gid: 'V-254163'
  tag rid: 'SV-254163r846577_rule'
  tag stig_id: 'NUTX-OS-000610'
  tag gtitle: 'SRG-OS-000254-GPOS-00095'
  tag fix_id: 'F-57599r846576_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
