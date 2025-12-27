control 'SV-208919' do
  title 'The tftp-server package must not be installed unless required.'
  desc 'Removing the "tftp-server" package decreases the risk of the accidental (or intentional) activation of tftp services.'
  desc 'check', 'Run the following command to determine if the "tftp-server" package is installed: 

# rpm -q tftp-server

If the package is installed and not documented and approved by the ISSO, this is a finding.'
  desc 'fix', 'The "tftp-server" package can be removed with the following command: 

# yum erase tftp-server'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9172r357737_chk'
  tag severity: 'medium'
  tag gid: 'V-208919'
  tag rid: 'SV-208919r793705_rule'
  tag stig_id: 'OL6-00-000222'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-9172r357738_fix'
  tag 'documentable'
  tag legacy: ['V-50567', 'SV-64773']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
