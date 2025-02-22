control 'SV-100257' do
  title 'The telnet-server package must not be installed.'
  desc %q(Removing the "telnet-server" package decreases the risk of the unencrypted telnet service's accidental (or intentional) activation.)
  desc 'check', 'Check if "telnet-server" is installed:

# rpm -q telnet-server

If there is a "telnet-server" package listed, this is a finding.'
  desc 'fix', 'To remove the "telnet-server" package use the following command:

rpm -e telnet-server'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89299r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89607'
  tag rid: 'SV-100257r1_rule'
  tag stig_id: 'VRAU-SL-000460'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-96349r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
