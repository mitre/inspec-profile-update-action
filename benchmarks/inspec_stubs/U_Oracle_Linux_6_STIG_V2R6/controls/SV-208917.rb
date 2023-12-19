control 'SV-208917' do
  title 'The ypserv package must not be installed.'
  desc 'Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.'
  desc 'check', 'Run the following command to determine if the "ypserv" package is installed: 

# rpm -q ypserv

If the package is installed, this is a finding.'
  desc 'fix', 'The "ypserv" package can be uninstalled with the following command: 

# yum erase ypserv'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9170r357731_chk'
  tag severity: 'medium'
  tag gid: 'V-208917'
  tag rid: 'SV-208917r793703_rule'
  tag stig_id: 'OL6-00-000220'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-9170r357732_fix'
  tag 'documentable'
  tag legacy: ['SV-64769', 'V-50563']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
