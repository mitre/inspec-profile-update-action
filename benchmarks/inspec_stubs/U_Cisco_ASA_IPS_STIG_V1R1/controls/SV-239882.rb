control 'SV-239882' do
  title 'The Cisco ASA must be configured to block outbound traffic containing DoS attacks by ensuring an intrusion prevention policy has been applied to outbound communications traffic.'
  desc 'The IDPS must include protection against DoS attacks that originate from inside the enclave which can affect either internal or external systems. These attacks may use legitimate or rogue endpoints from inside the enclave.

Installation of IDPS detection and prevention components (i.e., sensors) at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.

To comply with this requirement, the IDPS must inspect outbound traffic for indications of known and unknown DoS attacks. Sensor log capacity management, along with techniques that prevent the logging of redundant information during an attack, also guards against DoS attacks. This requirement is used in conjunction with other requirements which require configuration of security policies, signatures, rules, and anomaly detection techniques and are applicable to both inbound and outbound traffic.'
  desc 'check', 'Verify that an intrusion policy has been applied to access control rules.

Step 1: Navigate to  Configuration >> ASA FirePOWER Configuration >> Policies >> Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy configured for intrusion inspection using access control rules.

Step 3: Click the edit icon next to the rule you want to view. The access control rule editor appears.

Step 4: Verify that the rule action is set to Interactive Block or Interactive Block with reset.

Step 5: Select the Inspection tab. The Inspection tab appears.

Step 6: Verify that a system-provided or custom intrusion policy has been selected.

Note: An access control policy can have multiple access control rules associated with intrusion policies.
---------------------------------------------------
Verify that the ASA is configured to redirect all traffic to the FirePOWER service module.

Step 1: Verify that the FirePOWER service module has been deployed in inline mode as shown in the example below.

policy-map global_policy 
 class FIREPOWER_SFR
  sfr fail-open

Step 2: Verify that all traffic is redirected.

access-list FIREPOWER_REDIRECT extended permit ip any any
…
…
…
class-map FIREPOWER_SFR 
 match access-list FIREPOWER_REDIRECT

Note: Inbound and outbound traffic that is allowed by the ASA firewall is forwarded to the FirePOWER module. If the Cisco ASA FirePOWER module is configured in inline mode, the packet is inspected and dropped if it does not conform to access control policies. If the packet is compliant with access control policies, it is sent back to the ASA firewall for processing.

If the ASA is not configured to block outbound traffic containing DoS attacks by ensuring an intrusion prevention policy has been applied to outbound communications traffic, this is a finding.'
  desc 'fix', 'Configure access control rules to block non-compliant traffic.

Step 1: Navigate to  Configuration >> ASA FirePOWER Configuration >> Policies >> Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy configured for intrusion inspection using access control rules.

Step 3: Click the edit icon next to the rule you want to edit. The access control rule editor appears.

Step 4: Set the rule action Interactive Block or Interactive Block with reset.

Step 5: Select the Inspection tab. The Inspection tab appears.

Step 6: Select a system-provided or custom intrusion policy.

Step 7: Click Save to save the rule.
---------------------------------------------------
Configure the ASA to redirect all traffic to the FirePOWER module in inline mode as shown in the example below.

Step 1: Configure access list for all traffic.

ASA1(config)# access-list FIREPOWER_REDIRECT extended permit ip any any

Step 2: Create a class-map in order to match the traffic on an access list.

ASA1(config)# class-map FIREPOWER_SFR 
ASA1(config-cmap)# match access-list FIREPOWER_REDIRECT

Step 3: Configure deployment mode as inline.

ASA1(config)# policy-map global_policy 
ASA1(config-pmap)# class FIREPOWER_SFR
ASA1(config-pmap-c)# sfr fail-open'
  impact 0.5
  ref 'DPMS Target Cisco ASA IPS'
  tag check_id: 'C-43115r665957_chk'
  tag severity: 'medium'
  tag gid: 'V-239882'
  tag rid: 'SV-239882r665959_rule'
  tag stig_id: 'CASA-IP-000180'
  tag gtitle: 'SRG-NET-000192-IDPS-00140'
  tag fix_id: 'F-43074r665958_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
