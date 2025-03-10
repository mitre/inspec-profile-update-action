control 'SV-4336' do
  title 'The /etc/sysctl.conf file must have mode 0600 or less permissive.'
  desc "The sysctl.conf file specifies the values for kernel parameters to be set on boot.  These settings can affect the system's security."
  desc 'check', 'Check /etc/sysctl.conf permissions:

# ls –lL /etc/sysctl.conf

If /etc/sysctl.conf has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Use the chmod command to change the mode of the /etc/sysctl.conf file.
# chmod 0600 /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2141r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4336'
  tag rid: 'SV-4336r2_rule'
  tag stig_id: 'GEN000000-LNX00520'
  tag gtitle: 'GEN000000-LNX00520'
  tag fix_id: 'F-4247r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
