control 'SV-206798' do
  title 'The hardware Voice Video Endpoint must disable or restrict web browser capabilities permitting the endpoint to browse the internet or intranet.'
  desc 'Permitting hardware Voice Video Endpoints to browse the internet or enterprise intranet freely opens the endpoint to the possibility of inadvertently downloading malicious code to the endpoint for which it may have no protection. Voice Video Endpoints typically do not support host based intrusion detection or anti-virus software. While the downloaded malicious code might not affect the endpoint itself, the endpoint could be used by the malicious code as a launching pad into the network and attached workstations or servers.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint, this check procedure is Not Applicable.

Verify the hardware Voice Video Endpoint disables or restricts web browser capabilities permitting the endpoint to browse the Internet or intranet. External applications and services approved for accessibility on the Voice Video Endpoint and implemented by the enterprise are permissible.

If the hardware Voice Video does not disable or restrict web browser capabilities permitting the endpoint to browse the Internet or intranet, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint to disable or restrict web browser capabilities permitting the endpoint to browse the Internet or intranet.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7054r363917_chk'
  tag severity: 'medium'
  tag gid: 'V-206798'
  tag rid: 'SV-206798r604140_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00051'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7054r363918_fix'
  tag 'documentable'
  tag legacy: ['V-66783', 'SV-81273']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
