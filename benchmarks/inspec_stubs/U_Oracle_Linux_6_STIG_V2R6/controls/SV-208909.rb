control 'SV-208909' do
  title 'The audit system must be configured to audit changes to the /etc/sudoers file.'
  desc 'The actions taken by system administrators should be audited to keep a record of what was executed on the system, as well as, for accountability purposes.'
  desc 'check', 'To verify that auditing is configured for system administrator actions, run the following command:

$ sudo grep -w "/etc/sudoers" /etc/audit/audit.rules

If the system is configured to watch for changes to its sudoers configuration, a line should be returned (including "-p wa" indicating permissions that are watched).

If there is no output, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect administrator actions for all users and root. Add the following to "/etc/audit/audit.rules": 

-w /etc/sudoers -p wa -k actions'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9162r357707_chk'
  tag severity: 'low'
  tag gid: 'V-208909'
  tag rid: 'SV-208909r793695_rule'
  tag stig_id: 'OL6-00-000201'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-9162r357708_fix'
  tag 'documentable'
  tag legacy: ['SV-65345', 'V-51135']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
