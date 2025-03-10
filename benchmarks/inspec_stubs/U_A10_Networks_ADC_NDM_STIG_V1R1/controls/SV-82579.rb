control 'SV-82579' do
  title 'The A10 Networks ADC must not use SNMP Versions 1 or 2.'
  desc 'SNMP Versions 1 and 2 are not considered secure. Without the strong authentication and privacy that is provided by the SNMP Version 3 User-based Security Model (USM), an unauthorized user can gain access to network management information used to launch an attack against the network. SNMP Versions 1 and 2 cannot authenticate the source of a message nor can they provide encryption. Without authentication, it is possible for unauthorized users to exercise SNMP network management functions. It is also possible for unauthorized users to eavesdrop on management information as it passes from managed systems to the management system.

The A10 Networks ADC platforms support SNMPv3. The SNMP service is disabled by default and all traps are disabled by default. SNMP and SNMP trap are disabled on all data interfaces. Use the enable-management command to enable SNMP on the management interface. The OID for A10 Networks A10 Thunder Series and AX Series objects is 1.3.6.1.4.1.22610. Note: A10 Networks devices do not support SNMP “write” commands; this reduces the risk of the device configuration being modified by SNMP.'
  desc 'check', 'Review the device configuration.

The following command shows the running configuration and filters the output on the string "snmp-server":
show run | inc snmp-server

If the output shows servers using SNMPv1 or SNMPv2, this is a finding.'
  desc 'fix', 'The following commands enable SNMP and SNMP traps:
snmp-server enable
snmp-server enable traps
Note: This will enable sending all traps.

The following command sets Unique engineID:
snmp-server engineID [hex-string]

The commands below define SNMP OIDs to include when discovering the device via an SNMPv3 manager.

The following command defines the group view:
snmp-server view [view-name] 1.3.6 included

The following command defines SNMPv3 user-based groups:
snmp-server user [username] group [groupname] v3 [auth [md5 | sha] password [encrypted]]:
Note: Use the SHA option since MD5 is not compliant.

The following command defines the SNMPv3 console:
snmp host [IP_address] version v3 user [name] udp-port 162

The following command enables SNMP on the management interface:
enable-management service snmp management'
  impact 0.7
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68649r1_chk'
  tag severity: 'high'
  tag gid: 'V-68089'
  tag rid: 'SV-82579r1_rule'
  tag stig_id: 'AADC-NM-000119'
  tag gtitle: 'SRG-APP-000412-NDM-000331'
  tag fix_id: 'F-74203r1_fix'
  tag 'documentable'
  tag cci: ['CCI-003123']
  tag nist: ['MA-4 (6)']
end
