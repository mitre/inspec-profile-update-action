control 'SV-217991' do
  title 'The tftp-server package must not be installed unless required.'
  desc 'Removing the "tftp-server" package decreases the risk of the accidental (or intentional) activation of tftp services.'
  desc 'check', 'Run the following command to determine if the "tftp-server" package is installed: 

# rpm -q tftp-server

If the package is installed and not documented and approved by the ISSO, this is a finding.'
  desc 'fix', 'The "tftp-server" package can be removed with the following command: 

# yum erase tftp-server'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19472r376988_chk'
  tag severity: 'medium'
  tag gid: 'V-217991'
  tag rid: 'SV-217991r603264_rule'
  tag stig_id: 'RHEL-06-000222'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-19470r376989_fix'
  tag 'documentable'
  tag legacy: ['V-38606', 'SV-50407']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
