control 'SV-37258' do
  title 'The /etc/sysctl.conf file must have mode 0600 or less permissive.'
  desc "The sysctl.conf file specifies the values for kernel parameters to be set on boot.  These settings can affect the system's security."
  desc 'fix', 'Use the chmod command to change the mode of the /etc/sysctl.conf file.
# chmod 0600 /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-4336'
  tag rid: 'SV-37258r1_rule'
  tag stig_id: 'GEN000000-LNX00520'
  tag gtitle: 'GEN000000-LNX00520'
  tag fix_id: 'F-31204r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
