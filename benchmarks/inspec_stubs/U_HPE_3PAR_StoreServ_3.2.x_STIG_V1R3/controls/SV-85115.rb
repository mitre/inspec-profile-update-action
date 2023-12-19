control 'SV-85115' do
  title 'SNMP must be changed from default settings and must be configured on the storage system to provide alerts of critical events that impact system security.'
  desc 'Whether active or not, default SNMP passwords, users, and passphrases must be changed to maintain security. If the service is running with the default authenticators, anyone can gather data about the system and the network(s) and use the information to potentially compromise the integrity of the system or network(s).

The product must be configured to alert administrators when events occur that may impact system operation or security. The alerting mechanism must support secured options and configurations that can be audited.

'
  desc 'check', 'Verify a SNMPv3 user account is configured. Run the following command:

cli% showsnmpuser
Username | AuthProtocol | PrivProtocol
3parsnmpuser | HMAC SHA 96 | CFB128 AES 128

If the output is not displayed in the above format, this is a finding.

Identify the SNMP trap recipient and report SNMP configuration with the following command:

cli% showsnmpmgr
HostIP | Port | SNMPVersion | User
<snmp trap recipient IP> | 162 | 3 | 3parsnmpuser

If the SNMP trap recipient IP address is incorrect, this is a finding.
If the SNMP port is not "162", this is a finding.
If the SNMP version is not "3", this is a finding.
If the SNMP user ID is incorrect, this is a finding.

Generate a test trap:
cli% checksnmp

Trap sent to the following managers:
< IP address of trap recipient>

If the response does not indicate a trap was successfully sent, this is a finding.'
  desc 'fix', 'To configure SNMPv3 alert notifications, use this sequence of operations to create and enable an SNMPv3 user, and create associated keys for authentication and privacy:

First, create the "3parsnmpuser" on the host with the following command:

cli% createuser 3parsnmpuser all browse

Enter the password and retype the password to confirm.

Next, create the snmp user and associate that with the "3parsnmpuser" account on the host.

cli% createsnmpuser 3parsnmpuser

Enter the password and retype the password to confirm. 

Finally, add the IP address of the SNMPv3 trap recipient, where the permissions of the account are used:

cli% addsnmpmgr -pw <password> -version 3 -snmpuser 3parsnmpuser <ip address>'
  impact 0.5
  ref 'DPMS Target HPE 3PAR OS 3.2.2'
  tag check_id: 'C-70893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-70493'
  tag rid: 'SV-85115r1_rule'
  tag stig_id: 'HP3P-32-001300'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-76731r1_fix'
  tag satisfies: ['SRG-OS-000046-GPOS-00022', 'SRG-OS-000480-GPOS-00227', 'SRG-OS-000344-GPOS-00135']
  tag 'documentable'
  tag cci: ['CCI-000139', 'CCI-000366', 'CCI-001858']
  tag nist: ['AU-5 a', 'CM-6 b', 'AU-5 (2)']
end
