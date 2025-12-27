control 'SV-253514' do
  title 'DocAve must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems. Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services; however, doing so increases risk over limiting the services provided by any one component. To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Check the DocAve Manager communication port setting.
- On the DocAve 6 Manager server, open DocAve 6 Manager Configuration Tool from the Start Menu.
- Click "Control Service Configuration" on the left.
- Verify the Website Port.
- Click "Media Service Configuration" on the left.
- Verify the Media Service Port and Media Service Data Port.
- Click "Report Service Configuration" on the left.
- Verify the Report Service Port.

If any of these ports used by the DocAve Manager Services are not in accordance with the PPSM CAL, or otherwise AO Approved, this is a finding.

Check the DocAve Agent communication port setting.
- On the DocAve 6 Agent server, open DocAve 6 Agent Configuration Tool.
- Navigate to the Host And Port panel.
- Verify the Agent Port.

If the Agent Port is are not in accordance with the PPSM CAL, or otherwise AO Approved, this is a finding.

Check the DocAve Control Service update port setting.
- Log on to DocAve with admin account.
- On the Control Panel page, in the Update Manager section, click "Update Manager", then click "Update Settings".
- Navigate to the Update Port section.
- Verify the Update Port.

If the Update Port is are not in accordance with the PPSM CAL, or otherwise AO Approved, this is a finding.'
  desc 'fix', 'Configure the DocAve Manager communication port setting.
- On the DocAve 6 Manager server, open DocAve 6 Manager Configuration Tool.
- Click "Control Service Configuration" on the left.
- Change the Website Port.
- Click "Media Service Configuration" on the left.
- Change the Media Service Port and Media Service Data Port.
- Click "Report Service Configuration" on the left.
- Change the Report Service Port.
- Click "OK" to save settings.

Configure the DocAve Agent communication port setting.
- On the DocAve 6 Agent server, open DocAve 6 Agent Configuration Tool.
- Navigate to the Host And Port panel.
- Change the Agent Port.
- Click "OK" to save settings.

Configure the DocAve Control Service update port setting.
- Log on to DocAve with admin account.
- On the Control Panel page, in the Update Manager section, click "Update Manager", then click "Update Settings" button.
- Navigate to the Update Port section.
- Change the Update Port.
- Click Save button to save settings.'
  impact 0.5
  ref 'DPMS Target AvePoint DocAve 6'
  tag check_id: 'C-56966r836515_chk'
  tag severity: 'medium'
  tag gid: 'V-253514'
  tag rid: 'SV-253514r841862_rule'
  tag stig_id: 'DCAV-00-000054'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-56917r841862_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
