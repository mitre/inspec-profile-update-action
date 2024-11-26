control 'SV-222511' do
  title 'The application must enforce access restrictions associated with changes to application configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to application configuration may have significant effects on the overall security of the system.

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Accordingly, only qualified and authorized individuals should be allowed to obtain access to application components for the purposes of initiating changes, including upgrades and modifications.

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Review the application documentation and configuration settings.

Access the application configuration settings interface as a regular non-privileged user. Attempt to make configuration changes to the application.

If configuration changes can be made by regular non-privileged users, this is a finding.

Review the locations of all configuration files used by the application.

Examine the file permission settings and determine who has access to the configuration files.

If access permissions to configuration files are not restricted to application administrators, this is a finding.'
  desc 'fix', 'Configure the application to limit access to configuration settings to only authorized users.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24181r493441_chk'
  tag severity: 'medium'
  tag gid: 'V-222511'
  tag rid: 'SV-222511r849451_rule'
  tag stig_id: 'APSC-DV-001410'
  tag gtitle: 'SRG-APP-000380'
  tag fix_id: 'F-24170r493442_fix'
  tag 'documentable'
  tag legacy: ['SV-84127', 'V-69505']
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
