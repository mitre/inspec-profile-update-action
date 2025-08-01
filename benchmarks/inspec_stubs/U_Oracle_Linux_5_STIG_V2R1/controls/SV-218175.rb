control 'SV-218175' do
  title 'The /etc/sysctl.conf file must be owned by root.'
  desc "The sysctl.conf file specifies the values for kernel parameters to be set on boot.  These settings can affect the system's security."
  desc 'check', 'Check /etc/sysctl.conf ownership.
# ls -lL /etc/sysctl.conf 
If /etc/sysctl.conf is not owned by root, this is a finding.'
  desc 'fix', 'Use the chown command to change the owner of /etc/sysctl.conf to root:
# chown root /etc/sysctl.conf'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19650r561461_chk'
  tag severity: 'medium'
  tag gid: 'V-218175'
  tag rid: 'SV-218175r603259_rule'
  tag stig_id: 'GEN000000-LNX00480'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19648r561462_fix'
  tag 'documentable'
  tag legacy: ['V-4334', 'SV-62929']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
