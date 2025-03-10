control 'SV-206764' do
  title 'The hardware Voice Video Endpoint using SIP or AS-SIP signaling must prevent cross-site scripting attacks caused by improper filtering or validation of the content of SIP invitation fields.'
  desc 'A cross-site scripting vulnerability has been demonstrated by adding scripting code to the "From:" field in the SIP invite. Upon receiving the invite, the embedded code can be executed by a vulnerable embedded web server to download additional malicious code and launch an attack. The demonstration of the vulnerability also exists on www.securityfocus.com under Bugtraq ID: 25987, which pops up a specific alert box on the user’s workstation after downloading a SIP invite. 

While this vulnerability has been demonstrated on a specific IP phone, it could potentially affect all SIP-based endpoints or clients and their signaling partners. This vulnerability is a result of improper filtering or validation of the content of the various fields in the SIP invite and potentially the Session Description Protocol (SDP) portion of the invite. The injected code potentially causes malicious code to be run on the target device, to include an endpoint (hard or soft), a session controller, or any other SIP signaling partner. Additionally, this vulnerability may affect applications other than SIP VoIP clients, such as IM clients. A similar vulnerability results when URLs embedded in SIP messages are launched automatically.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint, this check procedure is Not Applicable.

Verify the hardware Voice Video Endpoint using SIP or AS-SIP signaling prevents cross-site scripting attacks caused by improper filtering or validation of the content of SIP invitation fields.

If the hardware Voice Video Endpoint does not use SIP or AS-SIP, this is not a finding. 

If the hardware Voice Video Endpoint does not prevent cross-site scripting attacks caused by improper filtering or validation of the content of SIP invitation fields, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint using SIP or AS-SIP signaling to prevent cross-site scripting attacks caused by improper filtering or validation of the content of SIP invitation fields.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7020r363815_chk'
  tag severity: 'medium'
  tag gid: 'V-206764'
  tag rid: 'SV-206764r604140_rule'
  tag stig_id: 'SRG-NET-000147-VVEP-00016'
  tag gtitle: 'SRG-NET-000147'
  tag fix_id: 'F-7020r363816_fix'
  tag 'documentable'
  tag legacy: ['SV-81201', 'V-66711']
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
