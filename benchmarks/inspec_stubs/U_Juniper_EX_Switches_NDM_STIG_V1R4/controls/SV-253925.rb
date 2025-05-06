control 'SV-253925' do
  title 'The Juniper EX switch must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, internet). A remote connection is any connection with a device communicating through an external network (e.g., the internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Review the network device configuration to verify SNMP messages are authenticated using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).

By default, SNMP is disabled. If used, verify SNMPv3 is configured (minimally) for authentication-sha. Although HMAC-MD5-96 is supported as required by RFC, Junos also supports HMAC-SHA, HMAC-SHA224/256/384/512. Configure the strongest HMAC supported by both the Juniper device and the Network Management System (NMS). 

[edit snmp v3]
usm {
    local-engine {
        user <SNMPv3 user> {
            authentication-sha {
                authentication-key "$8$aes256-gcm$hmac-sha2-256$100$2CM/LosUGF4$A...<snip>...rflBKxq/w+jaAVF55Bsc6PA"; ## SECRET-DATA
            }
        }
    }
}

If the network device is not configured to authenticate SNMP messages using a FIPS-validated HMAC, this is a finding.'
  desc 'fix', 'Configure the network device to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).

set snmp v3 usm local-engine user <SNMPv3 username> authentication-sha authentication-password "PSK"'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57377r843806_chk'
  tag severity: 'high'
  tag gid: 'V-253925'
  tag rid: 'SV-253925r879768_rule'
  tag stig_id: 'JUEX-NM-000480'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-57328r843807_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
