control 'SV-8733' do
  title 'Servers supporting the Voice Video and Unified Capability (UC) environment must be dedicated services, with unnecessary functions disabled or removed.'
  desc 'Voice Video and Unified Mail services are high-availability systems that must be separated from all other traffic. Unnecessary services will degrade performance. The RTS traffic may have latency issues if the support services also provide for other data elements and servers. This could result in lag or drop outs during calls, or denial of service in extreme circumstances.

The Defense Switched Network (DSN) STIG has been sunsetted. It is available on IASE in the Sunset Products page for telecommunications to be used for reference (https://iase.disa.mil/stigs/sunset/telecomm/Pages/index.aspx). The Voice Video Services Policy STIG, VVoIP STIG, Voice Video Endpoint SRG, and Voice Video Session Mgmt SRG contain the current guidance the DSN STIG covered. Additionally, the underlying OS, any attached database, and any applications providing ancillary functions must be assessed using the most appropriate guidance SRGs/STIGs.'
  desc 'check', 'Review the site documentation to confirm servers supporting the Voice Video and UC environment are dedicated services.

Ensure all unnecessary functions and applications are disabled or removed.

The Voice Video and UC core infrastructure includes (but is not limited to) session managers, voicemail and Unified Mail systems, media and signaling gateways, conference bridges, presence servers, and support services.

If the Voice Video and UC servers are not dedicated to applications supporting Voice Video operations, this is a finding.

If unnecessary applications for the server/device’s primary function are found, this is a finding.'
  desc 'fix', 'Configure the servers and devices supporting the Voice Video and UC environment without unnecessary functions and applications.

Dedicate servers in the Voice Video and UC core infrastructure to applications required for executing the primary function of the server or device, and those required for its support. Additionally, remove all unnecessary portions of the operating system such as sub-applications or files, and routines that are not required to support the telephony system.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23603r2_chk'
  tag severity: 'medium'
  tag gid: 'V-8247'
  tag rid: 'SV-8733r2_rule'
  tag stig_id: 'VVoIP 1050'
  tag gtitle: 'VVoIP 1050'
  tag fix_id: 'F-20122r2_fix'
  tag 'documentable'
end
