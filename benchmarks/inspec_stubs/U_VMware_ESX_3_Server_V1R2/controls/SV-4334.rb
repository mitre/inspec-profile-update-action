control 'SV-4334' do
  title 'The /etc/sysctl.conf file must be owned by root.'
  desc "The sysctl.conf file specifies the values for kernel parameters to be set on boot.  These settings can affect the system's security."
  desc 'check', 'Check /etc/sysctl.conf permissions: 
# ls -lL /etc/sysctl.conf 
If /etc/sysctl.conf is not owned by root, this is a finding.'
  desc 'fix', 'Use the chown command to change the owner of /etc/sysctl.conf to root:
# chown root /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-28800r1_chk'
  tag severity: 'medium'
  tag gid: 'V-4334'
  tag rid: 'SV-4334r2_rule'
  tag stig_id: 'GEN000000-LNX00480'
  tag gtitle: 'GEN000000-LNX00480'
  tag fix_id: 'F-4245r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
