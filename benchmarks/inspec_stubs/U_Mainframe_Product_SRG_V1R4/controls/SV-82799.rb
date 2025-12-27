control 'SV-82799' do
  title 'The Mainframe Product must enforce access restrictions associated with changes to application configuration.'
  desc 'Failure to provide logical access restrictions associated with changes to application configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals should be allowed to obtain access to application components for the purposes of initiating changes, including upgrades and modifications. 

Logical access restrictions include, for example, controls that restrict access to workflow automation, media libraries, abstract layers (e.g., changes implemented into third-party interfaces rather than directly into information systems), and change windows (e.g., changes occur only during specified times, making unauthorized changes easy to discover).'
  desc 'check', 'Examine Configuration settings.

Examine organization change management policies.

If the Mainframe Product does not enforce access restriction associated with changes to the application in accordance with change management policies, this is a finding.

If the Mainframe Product uses an external security manager (ESM), examine rules for change management access.

If there are no rules for this access or access is not restricted to users in accordance with change management policies, this is a finding.'
  desc 'fix', 'Configure Mainframe Product change management settings to enforce access restrictions associated with changes to application configuration to appropriate users according to organizational change policies.

If the Mainframe Product uses an ESM, configure rules to restrict access associated with application configuration change to appropriate users according to organizational change policies.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68869r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68309'
  tag rid: 'SV-82799r1_rule'
  tag stig_id: 'SRG-APP-000380-MFP-000187'
  tag gtitle: 'SRG-APP-000380-MFP-000187'
  tag fix_id: 'F-74423r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
