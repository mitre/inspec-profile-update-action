control 'SV-253926' do
  title 'The Juniper EX switch must be configured to authenticate Network Time Protocol sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'Review the network device configuration to determine if the network device authenticates NTP endpoints before establishing a local, remote, or network connection using authentication that is cryptographically based.

[edit system ntp]
authentication-key 1 type sha256 value "PSK"; ## SECRET-DATA
authentication-key 2 type sha1 value "PSK"; ## SECRET-DATA
server <address 1> key 1 prefer; ## SECRET-DATA
server <address 2> key 2; ## SECRET-DATA
trusted-key [ 1 2 ];

If the network device does not authenticate Network Time Protocol sources using authentication that is cryptographically based, this is a finding.'
  desc 'fix', 'Configure the network device to authenticate Network Time Protocol sources using authentication that is cryptographically based.

set system ntp authentication-key 1 type sha256
set system ntp authentication-key 1 value "PSK"
set system ntp authentication-key 2 type sha1
set system ntp authentication-key 2 value "PSK"
set system ntp server <address 1> key 1
set system ntp server <address 1> prefer
set system ntp server <address 2> key 2
set system ntp trusted-key 1
set system ntp trusted-key 2'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57378r843809_chk'
  tag severity: 'low'
  tag gid: 'V-253926'
  tag rid: 'SV-253926r843811_rule'
  tag stig_id: 'JUEX-NM-000490'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-57329r843810_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
