control 'SV-256843' do
  title 'Compliance Guardian must be configured to prohibit or restrict the use of organization-defined functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems. Applications are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., email and web services); however, doing so increases risk over limiting the services provided by any one component. To support the requirements and principles of least functionality, the application must support the organizational requirements providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Check the Compliance Guardian Manager communication port setting.
- On the Compliance Guardian Manager server, open "Compliance Guardian Manager Configuration Tool" from the Start Menu.
- Click "Control Service Configuration" on the left.
- Verify the Website Port.

If any ports used by the Compliance Guardian Manager Services are not in accordance with the PPSM CAL or are not AO approved, this is a finding.

Check the Compliance Guardian Agent communication port setting.
- On the Compliance Guardian Agent server, open "Compliance Guardian Agent Configuration Tool".
- Navigate to the "Host And Port" panel.
- Verify the Agent Port.

If the Agent Port is are not in accordance with the PPSM CAL or are not AO approved, this is a finding.

Check the Compliance Guardian Control Service update port setting.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the License and Update section, click "Update Manager", then click "Settings".
- Verify the "Specify a port number" to install the update.

If the Update Port is not in accordance with the PPSM CAL or is not AO approved, this is a finding.'
  desc 'fix', 'Configure the Compliance Guardian Manager communication port setting.
- On the Compliance Guardian Manager server, open the "Compliance Guardian Manager Configuration Tool" from the Start Menu.
- Click "Control Service Configuration" on the left.
- Change the Website Port.
- Click "OK" to save settings.

Configure the Compliance Guardian Agent communication port setting.
- On the Compliance Guardian Agent server, open "Compliance Guardian Agent Configuration Tool".
- Navigate to the "Host And Port" panel.
- Change the Agent Port.
- Click "OK" to save settings.

Configure the Compliance Guardian Control Service update port setting.
- Log on to Compliance Guardian with admin account.
- On the Control Panel page in the License and Update section, click "Update Manager", then click "Settings".
- Change the "Specify a port number" to install the update.
- Click "Save" to save settings.'
  impact 0.5
  ref 'DPMS Target AvePoint Compliance Guardian'
  tag check_id: 'C-60518r890137_chk'
  tag severity: 'medium'
  tag gid: 'V-256843'
  tag rid: 'SV-256843r890139_rule'
  tag stig_id: 'APCG-00-000020'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-60461r890138_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
