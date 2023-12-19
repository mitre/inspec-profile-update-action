control 'SV-99145' do
  title 'The telnet-server package must not be installed.'
  desc %q(Removing the "telnet-server" package decreases the risk of the unencrypted telnet service's accidental (or intentional) activation.)
  desc 'check', 'Check if "telnet-server" package is installed:

# rpm -q telnet-server

If there is a "telnet-server" package listed, this is a finding.'
  desc 'fix', 'To remove the "telnet-server" package use the following command:

rpm -e telnet-server'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88187r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88495'
  tag rid: 'SV-99145r1_rule'
  tag stig_id: 'VROM-SL-000455'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-95237r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
