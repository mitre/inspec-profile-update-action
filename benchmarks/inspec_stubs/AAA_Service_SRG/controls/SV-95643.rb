control 'SV-95643' do
  title 'AAA Services must be configured to protect the confidentiality and integrity of all information at rest.'
  desc 'Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive and tape drive) within an organizational information system. Mobile devices, laptops, desktops, and storage devices can be either lost or stolen, and the contents of their data storage (e.g., hard drives and non-volatile memory) can be read, copied, or altered. Applications and application users generate information throughout the course of their application use.

This requirement addresses protection of user-generated data, as well as, operating system-specific configuration data. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate, in accordance with the security category and/or classification of the information.'
  desc 'check', 'Verify AAA Services are configured to protect the confidentiality and integrity of all information at rest. AAA Services may leverage the capability of an operating system or purpose-built module for this purpose. Potential locations include the local file system where configurations and events are stored or in a related database table.

If AAA Services are not configured to protect the confidentiality and integrity of all information at rest, this is a finding.'
  desc 'fix', 'Configure AAA Services to protect the confidentiality and integrity of all information at rest. AAA Services may leverage the capability of an operating system or require the use of a purpose-built module for this purpose. Potential locations include the local file system where configurations and events are stored or in a related database table.'
  impact 0.7
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80671r1_chk'
  tag severity: 'high'
  tag gid: 'V-80933'
  tag rid: 'SV-95643r1_rule'
  tag stig_id: 'SRG-APP-000231-AAA-000610'
  tag gtitle: 'SRG-APP-000231-AAA-000610'
  tag fix_id: 'F-87789r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
