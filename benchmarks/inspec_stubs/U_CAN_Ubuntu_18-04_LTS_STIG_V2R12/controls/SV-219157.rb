control 'SV-219157' do
  title 'The Ubuntu operating system must not have the Network Information Service (NIS) package installed.'
  desc 'Removing the Network Information Service (NIS) package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.'
  desc 'check', 'Verify that the Network Information Service (NIS) package is not installed on the Ubuntu operating system.

Check to see if the NIS package is installed with the following command:

# dpkg -l | grep nis

If the NIS package is installed, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to disable non-essential capabilities by removing the Network Information Service (NIS) package from the system with the following command:

# sudo apt-get remove nis'
  impact 0.7
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20882r304799_chk'
  tag severity: 'high'
  tag gid: 'V-219157'
  tag rid: 'SV-219157r610963_rule'
  tag stig_id: 'UBTU-18-010018'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-20881r304800_fix'
  tag 'documentable'
  tag legacy: ['SV-109643', 'V-100539']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
