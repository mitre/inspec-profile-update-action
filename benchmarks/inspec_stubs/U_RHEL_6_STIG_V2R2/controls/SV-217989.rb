control 'SV-217989' do
  title 'The ypserv package must not be installed.'
  desc 'Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.'
  desc 'check', 'Run the following command to determine if the "ypserv" package is installed: 

# rpm -q ypserv


If the package is installed, this is a finding.'
  desc 'fix', 'The "ypserv" package can be uninstalled with the following command: 

# yum erase ypserv'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19470r376982_chk'
  tag severity: 'medium'
  tag gid: 'V-217989'
  tag rid: 'SV-217989r603264_rule'
  tag stig_id: 'RHEL-06-000220'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-19468r376983_fix'
  tag 'documentable'
  tag legacy: ['V-38603', 'SV-50404']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
