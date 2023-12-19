control 'SV-216237' do
  title 'The operating system must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial of service attacks.'
  desc 'In the case of denial of service attacks, care must be taken when designing the operating system so as to ensure that the operating system makes the best use of system resources.'
  desc 'check', 'Determine active Ethernet interfaces and note each LINK name and SPEED-DUPLEX:

# dladm show-ether -Z | egrep "LINK|up"

LINK PTYPE STATE AUTO SPEED-DUPLEX PAUSE
net0 current up yes 1G-f bi
net1 current up yes 100m-f bi

Determine the OS version you are currently securing:

# uname –v

For Solaris 11, 11.1, 11.2, and 11.3:

# dladm show-linkprop net0 | egrep "LINK|en_" | sort|uniq

LINK PROPERTY PERM VALUE EFFECTIVE DEFAULT POSSIBLE
net0 en_1000fdx_cap rw 1 1 0 1,0
net0 en_1000hdx_cap r- 0 0 0 1,0
net0 en_100fdx_cap rw 1 1 1 1,0
net0 en_100hdx_cap rw 1 1 1 1,0
net0 en_10fdx_cap rw 1 1 1 1,0
net0 en_10gfdx_cap -- -- -- 0 1,0
net0 en_10hdx_cap rw 1 1 1 1,0
net0 en_25gfdx_cap -- -- -- 0 1,0
net0 en_40gfdx_cap -- -- -- 0 1,0

# dladm show-linkprop net1 | egrep "LINK|en_" | sort|uniq

LINK PROPERTY PERM VALUE EFFECTIVE DEFAULT POSSIBLE
net1 en_1000fdx_cap rw 0 0 0 1,0
net1 en_1000hdx_cap r- 0 0 0 1,0
net1 en_100fdx_cap rw 1 1 1 1,0
net1 en_100hdx_cap rw 1 1 1 1,0
net1 en_10fdx_cap rw 1 1 1 1,0
net1 en_10gfdx_cap -- -- -- 0 1,0
net1 en_10hdx_cap rw 1 1 1 1,0
net1 en_25gfdx_cap -- -- -- 0 1,0
net1 en_40gfdx_cap -- -- -- 0 1,0

For Solaris 11.4 or newer:

# dladm show-linkprop -p speed-duplex net0

LINK PROPERTY PERM VALUE EFFECTIVE DEFAULT POSSIBLE
net0 speed-duplex rw 1g-f,100m-f, 1g-f,100m-f, 100m-f, 1g-f,100m-f,
100m-h, 100m-h, 100m-h, 100m-h,10m-f,
10m-f,10m-h 10m-f,10m-h 10m-f, 10m-h
10m-h

# dladm show-linkprop -p speed-duplex net1

LINK PROPERTY PERM VALUE EFFECTIVE DEFAULT POSSIBLE
net1 speed-duplex rw 100m-f 100m-f 100m-f, 1g-f,100m-f,
100m-h, 100m-h,10m-f,
10m-f, 10m-h
10m-h

For each link, determine if its current speed-duplex settings VALUE field is appropriate for managing any excess bandwidth capacity based on its POSSIBLE settings field; if not, this is a finding.'
  desc 'fix', 'The Network Management profile is required.

Set each link’s speed-duplex protection to an appropriate value based on each configured network interface’s POSSIBLE settings.

Determine the OS version you are currently securing:

# uname –v

For Solaris 11, 11.1, 11.2, and 11.3:

# pfexec dladm set-linkprop -p en_1000fdx_cap=1 net1

For Solaris 11.4 or newer:

# pfexec dladm set-linkprop -p speed-duplex=1g-f,100m-f net1'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-36493r603082_chk'
  tag severity: 'medium'
  tag gid: 'V-216237'
  tag rid: 'SV-216237r603268_rule'
  tag stig_id: 'SOL-11.1-090280'
  tag gtitle: 'SRG-OS-000142'
  tag fix_id: 'F-36457r603083_fix'
  tag 'documentable'
  tag legacy: ['SV-60771', 'V-47899']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
