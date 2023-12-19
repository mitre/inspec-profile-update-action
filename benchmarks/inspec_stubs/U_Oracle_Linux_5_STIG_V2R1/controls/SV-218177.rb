control 'SV-218177' do
  title 'The /etc/sysctl.conf file must have mode 0600 or less permissive.'
  desc "The sysctl.conf file specifies the values for kernel parameters to be set on boot.  These settings can affect the system's security."
  desc 'check', 'Check /etc/sysctl.conf permissions:

# ls -lL /etc/sysctl.conf

If /etc/sysctl.conf has a mode more permissive than 0600, this is a finding.'
  desc 'fix', 'Use the chmod command to change the mode of the /etc/sysctl.conf file.
# chmod 0600 /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19652r561467_chk'
  tag severity: 'medium'
  tag gid: 'V-218177'
  tag rid: 'SV-218177r603259_rule'
  tag stig_id: 'GEN000000-LNX00520'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19650r561468_fix'
  tag 'documentable'
  tag legacy: ['V-4336', 'SV-62963']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
