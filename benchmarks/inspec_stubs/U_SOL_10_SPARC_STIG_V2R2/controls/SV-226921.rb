control 'SV-226921' do
  title 'The telnet daemon must not be running.'
  desc 'The telnet daemon provides a typically unencrypted remote access service which does not provide for the confidentiality and integrity of user passwords or the remote session.  If a privileged user were to log on using this service, the privileged user password could be compromised.

'
  desc 'check', 'Determine if the telnet daemon is running. 

# svcs telnet

If the telnet service is enabled, this is a finding.'
  desc 'fix', 'Disable the telnet daemon. 

# svcadm disable telnet
# svcadm refresh inetd'
  impact 0.7
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29083r485059_chk'
  tag severity: 'high'
  tag gid: 'V-226921'
  tag rid: 'SV-226921r603265_rule'
  tag stig_id: 'GEN003850'
  tag gtitle: 'SRG-OS-000074'
  tag fix_id: 'F-29071r485060_fix'
  tag satisfies: ['SRG-OS-000074', 'SRG-OS-000520']
  tag 'documentable'
  tag legacy: ['V-24386', 'SV-39864']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
