control 'SV-234201' do
  title 'The FortiGate device must authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, internet). A remote connection is any connection with a device communicating through an external network (e.g., internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', "Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click SNMP.
3. Verify the SNMPv3 settings are configured and enabled.
4. Select each SNMPv3 user and click Edit.
5. On Security Level, verify the SNMPv3 user is configured to use SHA256 as the Authentication Algorithm.

If the FortiGate device is not configured to authenticate SNMP messages using a FIPS-validated HMAC, this is a finding.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:

     # show full-configuration system snmp user | grep -i 'security-level\\ |auth-proto'

For each SNMPv3 user, the output should be similar to:

          set security-level auth
          set auth-proto sha256

If the security-level parameter is not set to auth or auth-priv, and the auth-proto is not set to SHA, this is a finding."
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Click System.
2. Click SNMP.
3. Select each SNMPv3 user.
4. Click Edit.
5. On Security Level, click Authentication.
6. Select SHA256 for the Authentication Algorithm.
7. Change the Password if required.
8. Click OK.
9. Click Apply.

or 

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config system snmp user
     #    edit {NAME}
     #    set status enable
     #    set security-level auth
     #    set auth-proto sha256
     #    set auth-pwd {PASSWORD}
     #    next
     # end'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall NDM'
  tag check_id: 'C-37386r611790_chk'
  tag severity: 'medium'
  tag gid: 'V-234201'
  tag rid: 'SV-234201r850532_rule'
  tag stig_id: 'FGFW-ND-000210'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-37351r850531_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
