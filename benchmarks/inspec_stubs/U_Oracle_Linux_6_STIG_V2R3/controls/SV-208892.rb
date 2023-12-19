control 'SV-208892' do
  title 'The audit system must be configured to audit modifications to the systems Mandatory Access Control (MAC) configuration (SELinux).'
  desc "The system's mandatory access policy (SELinux) should not be arbitrarily changed by anything other than administrator action. All changes to MAC policy should be audited."
  desc 'check', 'To determine if the system is configured to audit changes to its SELinux configuration files, run the following command:

$ sudo grep -w "/etc/selinux" /etc/audit/audit.rules

If the system is configured to watch for changes to its SELinux configuration, a line should be returned (including "-p wa" indicating permissions that are watched).

If the system is not configured to audit attempts to change the MAC policy, this is a finding.'
  desc 'fix', 'Add the following to "/etc/audit/audit.rules": 

-w /etc/selinux/ -p wa -k MAC-policy'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9145r357656_chk'
  tag severity: 'low'
  tag gid: 'V-208892'
  tag rid: 'SV-208892r603263_rule'
  tag stig_id: 'OL6-00-000183'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9145r357657_fix'
  tag 'documentable'
  tag legacy: ['V-51171', 'SV-65381']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
