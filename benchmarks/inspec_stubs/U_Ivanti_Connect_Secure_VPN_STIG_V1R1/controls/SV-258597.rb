control 'SV-258597' do
  title 'The ICS that provides a Simple Network Management Protocol (SNMP) Network Management System (NMS) must configure SNMPv3 to use FIPS-validated AES cipher block algorithm.'
  desc 'Without device-to-device authentication, communications with malicious devices may be established. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

SNMPv3 supports authentication, authorization, access control, and privacy, while previous versions of the protocol contained well-known security weaknesses, which were easily exploited. SNMPv3 can be configured for identification and bidirectional, cryptographically based authentication.

A typical SNMP implementation includes three components: managed device, SNMP agent, and NMS. The SNMP agent is the SNMP process that resides on the managed device and communicates with the network management system. The NMS is a combination of hardware and software that is used to monitor and administer a network. The SNMP data is stored in a highly structured, hierarchical format known as a management information base (MIB). The SNMP manager collects information about network connectivity, activity, and events by polling managed devices.

SNMPv3 defines a user-based security model (USM), and a view-based access control model (VACM). SNMPv3 USM provides data integrity, data origin authentication, message replay protection, and protection against disclosure of the message payload. SNMPv3 VACM provides access control to determine whether a specific type of access (read or write) to the management information is allowed. Implement both VACM and USM for full protection.

SNMPv3 server services must not be configured on products whose primary purpose is not to provide SNMP services. SNMP client services may be configured on the VPN gateway, application, or operating system to allow limited monitoring or querying of the device from by an SNMP server for management purposes. SNMP of any version will not be used to make configuration changes to the device. SNMPv3 must be disabled by default and enabled only if used. SNMP v3 provides security feature enhancements to SNMP, including encryption and message authentication.

Currently, the AES cipher block algorithm can be used for both applying cryptographic protection (e.g., encryption) and removing or verifying the protection that was previously applied (e.g., decryption) in DOD. The use of FIPS-approved algorithms for both cryptographic mechanisms is required. If any version of SNMP is used for remote administration, default SNMP community strings such as "public" and "private" should be removed before real community strings are put into place. If the defaults are not removed, an attacker could retrieve real community strings from the device using the default string.'
  desc 'check', 'In the ICS Web UI, navigate to System >> Log/Monitoring >> SNMP.

Under "User 1", if a user configuration in AuthPriv is not using at least SHA and CFB-AES-128, this is a finding.'
  desc 'fix', 'Only the relevant portion of the SNMP configuration is highlighted here.

In the ICS Web UI, navigate to System >> Log/Monitoring >> SNMP.
1. Under "User 1", type in a valid username. Select "AuthPriv". The priv protocol must be set to at least CFB-AES-128. 
2. Type in the priv password.'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure VPN'
  tag check_id: 'C-62337r930477_chk'
  tag severity: 'medium'
  tag gid: 'V-258597'
  tag rid: 'SV-258597r930479_rule'
  tag stig_id: 'IVCS-VN-000440'
  tag gtitle: 'SRG-NET-000550-VPN-002360'
  tag fix_id: 'F-62246r930478_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
