control 'SV-239890' do
  title 'The Cisco ASA must be configured to block inbound traffic containing unauthorized activities or conditions.'
  desc "If inbound communications traffic is not continuously monitored for unusual/unauthorized activities or conditions, there will be times when hostile activity may not be noticed and defended against. 

Although some of the components in the site's content scanning solution may be used for periodic scanning assessment, the IDPS sensors and other components must provide continuous, 24 hours a day, 7 days a week monitoring. 

Unusual/unauthorized activities or conditions related to information system inbound communications traffic include, for example, internal traffic that indicates the presence of malicious code within organizational information systems or propagating among system components, the unauthorized exporting of information, or signaling to external information systems. Anomalies within organizational information systems include, for example, large file transfers, long-time persistent connections, use of unusual protocols and ports, and communications with suspected or known malicious external entities."
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

If the ASA is not configured to block inbound traffic containing unauthorized activities or conditions, this is a finding.'
  desc 'fix', 'Configure access control rules to block non-compliant traffic.

Step 1: Navigate to  Configuration >> ASA FirePOWER Configuration >> Policies >> Access Control Policy. The Access Control Policy page appears.

Step 2: Click the edit icon next to the access control policy configured for intrusion inspection using access control rules.

Step 3: Click the edit icon next to the rule you want to edit. The access control rule editor appears.

Step 4: Set the rule action to Interactive Block or Interactive Block with reset.

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
  tag check_id: 'C-43123r665981_chk'
  tag severity: 'medium'
  tag gid: 'V-239890'
  tag rid: 'SV-239890r665983_rule'
  tag stig_id: 'CASA-IP-000500'
  tag gtitle: 'SRG-NET-000390-IDPS-00212'
  tag fix_id: 'F-43082r665982_fix'
  tag 'documentable'
  tag cci: ['CCI-002661']
  tag nist: ['SI-4 (4) (b)']
end
