control 'SV-26525' do
  title 'The audit system must be configured to audit the loading and unloading of dynamic kernel modules.'
  desc 'Actions concerning dynamic kernel modules must be recorded as they are substantial events.  Dynamic kernel modules can increase the attack surface of a system.  A malicious kernel module can be used to substantially alter the functioning of a system, often with the purpose of hiding a compromise from the SA.'
  desc 'check', 'Check /etc/audit/audit_site.conf file to determine if syscalls handling kernel modules are audited.
# egrep -i "admin|modload|moduload|modpath" /etc/audit/audit_site.conf

All of the above syscalls must be defined in the file, otherwise this is a finding.'
  desc 'fix', 'Edit /etc/audit/audit_site.conf and add the admin, modload, moduload, and modpath syscalls to the list of events to be audited.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36447r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22383'
  tag rid: 'SV-26525r2_rule'
  tag stig_id: 'GEN002825'
  tag gtitle: 'GEN002825'
  tag fix_id: 'F-31786r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000126']
  tag nist: ['AU-2 c']
end
