control 'SV-217979' do
  title 'The audit system must be configured to audit changes to the /etc/sudoers file.'
  desc 'The actions taken by system administrators should be audited to keep a record of what was executed on the system, as well as, for accountability purposes.'
  desc 'check', 'To verify that auditing is configured for system administrator actions, run the following command: 

$ sudo grep -w "/etc/sudoers" /etc/audit/audit.rules

If the system is configured to watch for changes to its sudoers configuration, a line should be returned (including "-p wa" indicating permissions that are watched). 

If there is no output, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect administrator actions for all users and root. Add the following to "/etc/audit/audit.rules": 

-w /etc/sudoers -p wa -k actions'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19460r376952_chk'
  tag severity: 'low'
  tag gid: 'V-217979'
  tag rid: 'SV-217979r603264_rule'
  tag stig_id: 'RHEL-06-000201'
  tag gtitle: 'SRG-OS-000064'
  tag fix_id: 'F-19458r376953_fix'
  tag 'documentable'
  tag legacy: ['V-38578', 'SV-50379']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
