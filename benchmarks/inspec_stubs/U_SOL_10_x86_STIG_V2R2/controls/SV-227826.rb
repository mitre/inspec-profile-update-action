control 'SV-227826' do
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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29988r489844_chk'
  tag severity: 'high'
  tag gid: 'V-227826'
  tag rid: 'SV-227826r603266_rule'
  tag stig_id: 'GEN003850'
  tag gtitle: 'SRG-OS-000074'
  tag fix_id: 'F-29976r489845_fix'
  tag satisfies: ['SRG-OS-000074', 'SRG-OS-000520']
  tag 'documentable'
  tag legacy: ['V-24386', 'SV-39864']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
