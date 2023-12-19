control 'SV-216819' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to authenticate all received MSDP packets.'
  desc 'MSDP peering with customer network routers presents additional risks to the core, whether from a rogue or misconfigured MSDP-enabled router. 

MSDP password authentication is used to validate each segment sent on the TCP connection between MSDP peers, protecting the MSDP session against the threat of spoofed packets being injected into the TCP connection stream.'
  desc 'check', 'Review the router configuration to determine if received MSDP packets are authenticated.

router msdp
 peer x.14.2.1
  password encrypted 094E410B1B1C
  remote-as nn
 !
 peer x.15.3.5
  password encrypted 04500A140A2F
  remote-as nn
 !
!

If the router does not require MSDP authentication, this is a finding.'
  desc 'fix', 'Configure the router to authenticate MSDP messages as shown in the following example:

RP/0/0/CPU0:R2(config)#router msdp
RP/0/0/CPU0:R2(config-msdp)#peer x.14.2.1
RP/0/0/CPU0:R2(config-msdp-peer)#password clear xxxxxxxxxxxx
RP/0/0/CPU0:R2(config-msdp-peer)#exit
RP/0/0/CPU0:R2(config-msdp)#peer x.15.3.5
RP/0/0/CPU0:R2(config-msdp-peer)#password clear xxxxxxxxxxx 
RP/0/0/CPU0:R2(config-msdp-peer)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18051r288831_chk'
  tag severity: 'medium'
  tag gid: 'V-216819'
  tag rid: 'SV-216819r856456_rule'
  tag stig_id: 'CISC-RT-000910'
  tag gtitle: 'SRG-NET-000343-RTR-000002'
  tag fix_id: 'F-18049r288832_fix'
  tag 'documentable'
  tag legacy: ['SV-105983', 'V-96845']
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
