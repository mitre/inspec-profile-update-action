control 'SV-218176' do
  title 'The /etc/sysctl.conf file must be group-owned by root.'
  desc "The sysctl.conf file specifies the values for kernel parameters to be set on boot.  These settings can affect the system's security."
  desc 'check', 'Check /etc/sysctl.conf group ownership: 
# ls -lL /etc/sysctl.conf 
If /etc/sysctl.conf is not group-owned by root, this is a finding.'
  desc 'fix', 'Use the chgrp command to change the group owner of /etc/sysctl.conf to root:
# chgrp root /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19651r561464_chk'
  tag severity: 'medium'
  tag gid: 'V-218176'
  tag rid: 'SV-218176r603259_rule'
  tag stig_id: 'GEN000000-LNX00500'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19649r561465_fix'
  tag 'documentable'
  tag legacy: ['V-4335', 'SV-62951']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
