control 'SV-217337' do
  title 'The Juniper router must be configured to authenticate SNMP messages using a FIPS-validated Keyed-Hash Message Authentication Code (HMAC).'
  desc 'Without authenticating devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network, Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to only apply the requirement to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the example below.

snmp {
    v3 {
        usm {
            local-engine {
                user R5_NMS {
                    authentication-sha {
                        authentication-key "$8$vOiLX-Vb2oaUwsJDiHmPz3690BcSevM"; ## SECRET-DATA
                    }
                }
            }
        }
        target-address NMS_HOST {
            address x.x.x.x;
            address-mask 255.255.255.0;
            tag-list NMS;
            target-parameters TP1;
        }
        target-parameters TP1 {
            parameters {
                message-processing-model v3;
                security-model usm;
                security-level authentication;
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

If the router is not configured to authenticate SNMP messages using a FIPS-validated HMAC, this is a finding.'
  desc 'fix', 'Configure the router to authenticate SNMP messages as shown in the example below.

[edit snmp]
set v3 usm local-engine user R5_NMS authentication-sha authentication-password xxxxxxxxxx
set v3 target-address NMS_HOST address x.x.x.x

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
set v3 target-parameters TP1 parameters security-level authentication
set v3 snmp-community index1 security-name R5_NMS tag NMS
set v3 notify SEND_TRAPS type trap tag NMS'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18564r296589_chk'
  tag severity: 'medium'
  tag gid: 'V-217337'
  tag rid: 'SV-217337r879768_rule'
  tag stig_id: 'JUNI-ND-001120'
  tag gtitle: 'SRG-APP-000395-NDM-000310'
  tag fix_id: 'F-18562r296590_fix'
  tag 'documentable'
  tag legacy: ['SV-101263', 'V-91163']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
