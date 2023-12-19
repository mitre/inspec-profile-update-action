control 'SV-222669' do
  title 'At least one application administrator must be registered to receive update notifications, or security alerts, when automated alerts are available.'
  desc 'Administrators should register for updates to all COTS and custom-developed software, so when security flaws are identified, they can be tracked for testing and updates of the application can be applied.

Admin personnel should be registered to receive updates to all components of the application, such as Web Server, Application Servers, and Database Servers. Also, if update notifications are provided for any custom-developed software, libraries or third-party tools, deployment personnel must also register for these updates.'
  desc 'check', 'Review the components of the application.

Ask the application representative to demonstrate deployment personnel are registered to receive notifications for update notification for all of the application components including custom-developed software, libraries and third-party tools.

If no deployment personnel are registered to receive the alerts, this is a finding.'
  desc 'fix', 'Register administrators to receive update notifications so they can patch and update applications and application components.'
  impact 0.3
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24339r493915_chk'
  tag severity: 'low'
  tag gid: 'V-222669'
  tag rid: 'SV-222669r508029_rule'
  tag stig_id: 'APSC-DV-003340'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24328r493916_fix'
  tag 'documentable'
  tag legacy: ['V-70417', 'SV-85039']
  tag cci: ['CCI-000366', 'CCI-001285']
  tag nist: ['CM-6 b', 'SI-5 a']
end
