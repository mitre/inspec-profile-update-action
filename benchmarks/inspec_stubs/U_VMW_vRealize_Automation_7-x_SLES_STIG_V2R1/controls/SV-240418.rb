control 'SV-240418' do
  title 'The yast2-tftp-server package must not be installed.'
  desc 'Removing the "yast2-tftp-server" package decreases the risk of the accidental (or intentional) activation of tftp services.'
  desc 'check', 'Check if "yast2-tftp-server" is installed:

# rpm -q yast2-tftp-server

If a "yast2-tftp-server" package is listed, this is a finding.'
  desc 'fix', 'To remove the "yast2-tftp-server" package, use the following command:

rpm -e yast2-tftp-server'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43651r670993_chk'
  tag severity: 'medium'
  tag gid: 'V-240418'
  tag rid: 'SV-240418r670995_rule'
  tag stig_id: 'VRAU-SL-000475'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-43610r670994_fix'
  tag 'documentable'
  tag legacy: ['SV-100263', 'V-89613']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
