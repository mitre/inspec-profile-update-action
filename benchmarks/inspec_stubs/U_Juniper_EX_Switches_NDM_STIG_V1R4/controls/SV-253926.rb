control 'SV-253926' do
  title 'The Juniper EX switch must use an an NTP service that is hosted by a trusted source or a DOD-compliant enterprise or local NTP server.'
  desc 'If a trusted time source is not used, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate which may hide attacks or result in inaccurate forensic analysis. 

The recommended solution is that the application or endpoint is configured to point to an enterprise or site-owned time server that is DOD-compliant (instead of directly to an NTP source as implied by the current wording of the requirement). Most products are unable to meet the requirement, but DISA can mitigate the risk by using a trusted time source. So the requirement should state that NTPS is used with USNO NTP as an alternative mitigation for this to be marked as Not a Finding.

More information can be found at:
https://www.cnmoc.usff.navy.mil/Our-Commands/United-States-Naval-Observatory/Precise-Time-Department/Network-Time-Protocol-NTP/DoD-Customer-Servers/

DOD users should not use tick, tock, or ntp2. There are also instructions for obtaining authenticated NTP at the site listed above.'
  desc 'check', 'Review the Juniper EX configuration to determine if it obtains time information from a trusted source.

[edit system ntp]
authentication-key 1 type sha256 value "PSK"; ## SECRET-DATA
authentication-key 2 type sha1 value "PSK"; ## SECRET-DATA
server <address 1> key 1 prefer; ## SECRET-DATA
server <address 2> key 2; ## SECRET-DATA
trusted-key [ 1 2 ];

If the network device does not support FIPS-validated algorithms, verify the network device configuration to determine NTP endpoints are authenticated before establishing the local, remote, or network connection using cryptographically based algorithms.
[edit system ntp]
authentication-key 3 type md5 value "PSK"; ## SECRET-DATA
server <address 3> key 3; ## SECRET-DATA
trusted-key [ 1 2 3 ];

If the Juniper EX switch is not configured to use an NTP service that is hosted by a trusted source or a DOD-compliant enterprise or local NTP server, this is a finding.'
  desc 'fix', 'Configure the network device to authenticate Network Time Protocol sources using FIPS-validated algorithms.

set system ntp authentication-key 1 type sha256
set system ntp authentication-key 1 value "PSK"
set system ntp authentication-key 2 type sha1
set system ntp authentication-key 2 value "PSK"
set system ntp server <address 1> key 1
set system ntp server <address 1> prefer
set system ntp server <address 2> key 2
set system ntp trusted-key 1
set system ntp trusted-key 2

If the network device does not support FIPS-validated algorithms, configure NTP authentication using cryptographically based algorithms.
set system ntp authentication-key 3 type md5
set system ntp authentication-key 3 value "PSK"
set system ntp server <address 3> key 3
set system ntp trusted-key 3'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57378r904441_chk'
  tag severity: 'low'
  tag gid: 'V-253926'
  tag rid: 'SV-253926r904442_rule'
  tag stig_id: 'JUEX-NM-000490'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-57329r904417_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
