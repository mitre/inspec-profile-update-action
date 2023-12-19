control 'SV-243199' do
  title 'The network device must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, internet). A remote connection is any connection with a device communicating through an external network (e.g., the internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and types) of devices that truly need to support this capability.'
  desc 'check', 'Review the device configuration to verify it is configured to use SNMPv3 with both SHA authentication and privacy using AES encryption.

Downgrades:
If the site is using Version 1 or Version 2 with all of the appropriate patches and has developed a migration plan to implement the Version 3 Security Model, this finding can be downgraded to a CAT II.

If the site is using Version 1 or Version 2 and has installed all of the appropriate patches or upgrades to mitigate any known security vulnerabilities, this finding can be downgraded to a CAT II. In addition, if the device does not support SNMPv3, this finding can be downgraded to a CAT II provided all of the appropriate patches to mitigate any known security vulnerabilities have been applied and a migration plan has been developed that includes the device upgrade to support Version 3 and the implementation of the Version 3 Security Model.

If the device is configured to use to anything other than SNMPv3 with at least SHA-1 and AES, this is a finding. 

Downgrades can be determined based on the criteria above.'
  desc 'fix', 'If SNMP is enabled, configure the network device to use SNMP Version 3 Security Model with FIPS 140-2 validated cryptography (i.e., SHA authentication and AES encryption).'
  impact 0.5
  ref 'DPMS Target Network WLAN Controller Mgmt'
  tag check_id: 'C-46474r720050_chk'
  tag severity: 'medium'
  tag gid: 'V-243199'
  tag rid: 'SV-243199r720052_rule'
  tag stig_id: 'WLAN-ND-001200'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-46431r720051_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
