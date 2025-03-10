control 'SV-255958' do
  title 'The Arista network device must be configured to synchronize internal system clocks using redundant authenticated time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions.

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DOD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DOD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.

'
  desc 'check', 'Determine if the network device is configured to synchronize internal information system clocks with authenticated primary and secondary time sources.

Verify the Arista network device configuration with the following example:

switch# show running-config | section ntp

ntp authentication-key 12 sha1 7 06131C2058470A58
ntp trusted-key 12
ntp authenticate servers
ntp local-interface Management1
ntp server 192.168.16.36 prefer key 12
ntp server 192.168.16.37 key 12

If the Arista network device is not configured to synchronize internal system clocks with the primary and secondary time sources, this is a finding.

If the Arista network device does not authenticate Network Time Protocol sources using authentication that is cryptographically based, this is a finding.'
  desc 'fix', 'Configure the Arista network device for at least two trusted time sources and to use cryptographic authentication with the following command example:

switch#config
switch(config)#ntp authentication-key 12 sha1 0 <key>
switch(config)#ntp trusted-key 12
switch(config)#ntp authenticate servers
switch(config)#ntp local-interface Management1
switch(config)#ntp server 192.168.16.36 prefer key 12
switch(config)#ntp server 192.168.16.37 key 12
switch(config)#exit

Configure the local time zone for the device.

switch#config
switch(config)#clock timezone <timezone>
switch(config)#exit'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59634r882214_chk'
  tag severity: 'medium'
  tag gid: 'V-255958'
  tag rid: 'SV-255958r882216_rule'
  tag stig_id: 'ARST-ND-000600'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-59577r882215_fix'
  tag satisfies: ['SRG-APP-000373-NDM-000298', 'SRG-APP-000374-NDM-000299', 'SRG-APP-000375-NDM-000300', 'SRG-APP-000395-NDM-000347']
  tag 'documentable'
  tag cci: ['CCI-001889', 'CCI-001890', 'CCI-001893', 'CCI-001967']
  tag nist: ['AU-8 b', 'AU-8 b', 'AU-8 (2)', 'IA-3 (1)']
end
