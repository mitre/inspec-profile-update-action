control 'SV-3196' do
  title 'The network device must use SNMP Version 3 Security Model with FIPS 140-2 validated cryptography for any SNMP agent configured on the device.'
  desc 'SNMP Versions 1 and 2 are not considered secure. Without the strong authentication and privacy that is provided by the SNMP Version 3 User-based Security Model (USM), an unauthorized user can gain access to network management information used to launch an attack against the network.'
  desc 'check', 'Review the device configuration to verify it is configured to use SNMPv3 with both SHA authentication and privacy using AES encryption.

Downgrades:
If the site is using Version 1 or Version 2 with all of the appropriate patches and has developed a migration plan to implement the Version 3 Security Model, this finding can be downgraded to a Category II.

If the targeted asset is running SNMPv3 and does not support SHA or AES, but the device is configured to use MD5 authentication and DES or 3DES encryption, then the finding can be downgraded to a Category III.

If the site is using Version 1 or Version 2 and has installed all of the appropriate patches or upgrades to mitigate any known security vulnerabilities, this finding can be downgraded to a Category II. In addition, if the device does not support SNMPv3, this finding can be downgraded to a Category III provided all of the appropriate patches to mitigate any known security vulnerabilities have been applied and has developed a migration plan that includes the device upgrade to support Version 3 and the implementation of the Version 3 Security Model.

If the device is configured to use to anything other than SNMPv3 with at least SHA-1 and AES, this is a finding. Downgrades can be determined based on the criteria above.'
  desc 'fix', 'If SNMP is enabled, configure the network device to use SNMP Version 3 Security Model with FIPS 140-2 validated cryptography (i.e., SHA authentication and AES encryption).'
  impact 0.7
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-3820r6_chk'
  tag severity: 'high'
  tag gid: 'V-3196'
  tag rid: 'SV-3196r4_rule'
  tag stig_id: 'NET1660'
  tag gtitle: 'An insecure version of SNMP is being used.'
  tag fix_id: 'F-3221r5_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
