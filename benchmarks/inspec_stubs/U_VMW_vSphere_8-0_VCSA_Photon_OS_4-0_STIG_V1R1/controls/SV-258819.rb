control 'SV-258819' do
  title 'The Photon operating system must not have the telnet package installed.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'At the command line, run the following command to verify telnet is not installed:

# rpm -qa | grep telnet

If any results are returned indicating telnet is installed, this is a finding.'
  desc 'fix', 'At the command line, run the following command:

# tdnf remove <package name>'
  impact 0.7
  ref 'DPMS Target VMware vSphere 8.0 VCSA Photon OS 4.0'
  tag check_id: 'C-62559r933516_chk'
  tag severity: 'high'
  tag gid: 'V-258819'
  tag rid: 'SV-258819r933518_rule'
  tag stig_id: 'PHTN-40-000040'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-62468r933517_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
