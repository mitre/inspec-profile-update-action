control 'SV-255995' do
  title 'The Arista MSDP router must be configured to limit the amount of source-active messages it accepts on per-peer basis.'
  desc 'To reduce any risk of a denial-of-service (DoS) attack from a rogue or misconfigured MSDP router, the router must be configured to limit the number of source-active messages it accepts from each peer.'
  desc 'check', 'To verify the MSDP peer and the sa-limit filter is configured, execute the command "show run | sec router msdp".

router msdp 
 peer 10.1.12.2
   sa-limit 500
 peer 10.1.55.78
   sa-limit 900

If the Arista router is not configured with a peer limit, this is a finding.'
  desc 'fix', 'Configure the Arista MSDP router to limit the amount of source-active messages it accepts from each peer.

!
router (config) #router msdp
router (config-router-msdp) #peer 10.1.1.5
router (config-router-msdp-peer 10.1.1.5) # sa-limit 500
router (config-router-msdp) #peer 10.1.55.78
router (config-router-msdp-peer 10.1.55.78) # sa-limit 900
router (config-router-msdp-peer 10.1.55.78) # exit'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59671r882325_chk'
  tag severity: 'low'
  tag gid: 'V-255995'
  tag rid: 'SV-255995r882327_rule'
  tag stig_id: 'ARST-RT-000090'
  tag gtitle: 'SRG-NET-000018-RTR-000009'
  tag fix_id: 'F-59614r882326_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
