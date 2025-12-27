control 'SV-95171' do
  title 'The Bromium vSentry client must include exceptions for HBSS to ensure interoperability and protect from attacks on critical files, applications, processes, registry settings, and attempts at executing unauthorized code in memory.'
  desc 'The monitoring agent will monitor and alert on attempts to attack critical files, applications, processes, and registry settings associated with the Bromium vSentry application itself, as well as attempts at executing unauthorized code in memory. All alerts will be sent to the BEC management server (along with any designated syslog destinations). Upon receipt of the alert, the system administrator must investigate and take appropriate action.

HBSS must be tuned to allow exceptions for the Bromium protection agent. Exceptions are detailed in the Bromium Secure Platform Deployment Guide at https://documentation.bromium.com/4_0/Deployment%20Guide/Bromium_Secure_Platform_Deployment_Guide_4_0_Update_3.pdf. Alert on attempts to attack critical files, applications, processes, registry settings, and attempts at executing unauthorized code in memory.'
  desc 'check', 'Inspect the HBSS configuration policy to verify exceptions for the Bromium directory and related settings.

If the endpoint running Bromium vSentry does include exceptions for HBSS ensure interoperability, this is a finding.'
  desc 'fix', 'Refer to the Bromium Secure Platform Deployment Guide at https://documentation.bromium.com/4_0/Deployment%20Guide/Bromium_Secure_Platform_Deployment_Guide_4_0_Update_3.pdf for detailed instructions on creating exceptions for HBSS.

Obtain approval from the ISSM or other approving authority for exceptions to HBSS.'
  impact 0.5
  ref 'DPMS Target Bromium Secure Platform'
  tag check_id: 'C-80139r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80467'
  tag rid: 'SV-95171r1_rule'
  tag stig_id: 'BROM-00-001085'
  tag gtitle: 'SRG-APP-000450'
  tag fix_id: 'F-87273r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
