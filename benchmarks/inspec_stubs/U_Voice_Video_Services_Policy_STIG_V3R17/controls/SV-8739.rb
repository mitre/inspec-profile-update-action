control 'SV-8739' do
  title 'The voicemail system and/or server must implement applicable SRG and/or STIG guidance.'
  desc 'Voice mail services are subject to the guidance and requirements in the Voice VIdeo STIGs. Older voice mail systems/servers commonly use proprietary Oss, while newer ones often run on Windows or Linux.

The Defense Switched Network (DSN) STIG has been sunsetted. It is available on IASE in the Sunset Products page for telecommunications to be used for reference (https://iase.disa.mil/stigs/sunset/telecomm/Pages/index.aspx). The Voice Video Services Policy STIG, VVoIP STIG, Voice Video Endpoint SRG, and Voice Video Session Mgmt SRG contain the current guidance the DSN STIG covered. Additionally, the underlying OS, any attached database, and any applications providing ancillary functions must be assessed using the most appropriate guidance SRGs/STIGs.'
  desc 'check', 'Review the site documentation to confirm all voicemail systems and servers implement the appropriate SRGs and STIGs. The server OS must be assessed using the Windows, Linux, or other appropriate STIG. The application and supporting services must be assessed using the appropriate (e.g., application, web server, database) SRGs and STIGs.

If the voicemail systems and servers are not assessed using the appropriate SRGs and STIGs, this is a finding.'
  desc 'fix', 'Ensure voicemail systems and servers are secured using the appropriate (e.g., application, web server, database, OS) SRGs and STIGs.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23617r2_chk'
  tag severity: 'low'
  tag gid: 'V-8253'
  tag rid: 'SV-8739r2_rule'
  tag stig_id: 'VVoIP 1040'
  tag gtitle: 'VVoIP 1040'
  tag fix_id: 'F-20134r2_fix'
  tag 'documentable'
end
