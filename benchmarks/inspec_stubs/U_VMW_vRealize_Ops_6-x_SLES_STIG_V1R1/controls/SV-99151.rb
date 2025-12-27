control 'SV-99151' do
  title 'The yast2-tftp-server package must not be installed.'
  desc 'Removing the "yast2-tftp-server" package decreases the risk of the accidental (or intentional) activation of tftp services.'
  desc 'check', 'Check if "yast2-tftp-server" package is installed:

# rpm -q yast2-tftp-server

If there is a "yast2-tftp-server" package listed, this is a finding.'
  desc 'fix', 'To remove the "yast2-tftp-server" package use the following command:

rpm -e yast2-tftp-server'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88193r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88501'
  tag rid: 'SV-99151r1_rule'
  tag stig_id: 'VROM-SL-000470'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-95243r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
