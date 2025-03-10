control 'SV-217338' do
  title 'The Juniper router must be configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm.'
  desc 'Without the strong encryption that is provided by the SNMP Version 3 User-based Security Model (USM), an unauthorized user can gain access to network management information that can be used to create a network outage.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the example below.

snmp {
    v3 {
        usm {
            local-engine {
                user R5_NMS {
                    authentication-sha {
                        authentication-key "$8$vOiLX-Vb2oaUwsJDiHmPz3690BcSevM"; ## SECRET-DATA
                    }
                    privacy-aes128 {
                        privacy-key "$8$3Q4T9CuOBESyK1IrvW87NwYgoDiPfz3nCs24Z"; ## SECRET-DATA
                    }
                }
            }
        }
        target-address NMS_HOST {
            address 10.1.58.2;
            address-mask 255.255.255.0;
            tag-list NMS;
            target-parameters TP1;
        }
        target-parameters TP1 {
            parameters {
                message-processing-model v3;
                security-model usm;
                security-level privacy;
                security-name R5_NMS;
            }
        }
        notify SEND_TRAPS {
            type trap;
            tag NMS;
        }
        snmp-community index1 {
            security-name R5_NMS;
            tag NMS;
        }
    }
} 

Note: SNMPv3 security level privacy also authenticates the messages using the configured HMAC.

If the router is not configured to encrypt SNMP messages using a FIPS 140-2 approved algorithm, this is a finding.'
  desc 'fix', 'Configure the router to encrypt SNMP messages using a FIPS 140-2 approved algorithm as shown in the example below.

[edit snmp]
set v3 usm local-engine user R5_NMS authentication-sha authentication-password xxxxxxxxxx
set v3 usm local-engine user R5_NMS privacy-aes128 privacy-password xxxxxxxxxx
set v3 target-address NMS_HOST address 10.1.58.2
edit v3 target-address NMS_HOST

[edit snmp v3 target-address NMS_HOST]
set address-mask 255.255.255.0
set tag-list NMS
set target-parameters TP1
exit

[edit snmp]
set v3 target-parameters TP1 parameters message-processing-model v3
set v3 target-parameters TP1 parameters security-model usm
set v3 target-parameters TP1 parameters security-name R5_NMS
set v3 target-parameters TP1 parameters security-level privacy
set v3 snmp-community index1 security-name R5_NMS tag NMS
set v3 notify SEND_TRAPS type trap tag NMS

Note: SNMPv3 security level privacy also authenticates the messages using the configured HMAC; hence, the authentication key must also be configured as shown in the example above.'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18565r296592_chk'
  tag severity: 'medium'
  tag gid: 'V-217338'
  tag rid: 'SV-217338r879768_rule'
  tag stig_id: 'JUNI-ND-001130'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-18563r296593_fix'
  tag 'documentable'
  tag legacy: ['SV-101265', 'V-91165']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
