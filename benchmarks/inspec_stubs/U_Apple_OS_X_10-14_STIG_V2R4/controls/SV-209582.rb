control 'SV-209582' do
  title 'The macOS system must cover or disable the built-in or attached camera when not in use.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect from collaborative computing devices (i.e. cameras) can result in subsequent compromises of organizational information. Providing easy methods to physically disconnect from such devices after a collaborative computing session helps to ensure that participants actually carry out the disconnect activity without having to go through complex and tedious procedures.

'
  desc 'check', 'If the device or operating system does not have a camera installed, this requirement is not applicable.

This requirement is not applicable to mobile devices (smartphones and tablets), where the use of the camera is a local AO decision.

This requirement is not applicable to dedicated VTC suites located in approved VTC locations that are centrally managed.

For an external camera, if there is not a method for the operator to manually disconnect camera at the end of collaborative computing sessions, this is a finding.

For a built-in camera, the camera must be protected by a camera cover (e.g. laptop camera cover slide) when not in use. If the built-in camera is not protected with a camera cover, or is not physically disabled, this is a finding. 

If the camera is not disconnected, covered or physically disabled, the following configuration is required:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep allowCamera

If the result is “allowCamera = 1” and the collaborative computing device has not been authorized for use, this is a finding.'
  desc 'fix', 'This setting is enforced using the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple OS X 10.14'
  tag check_id: 'C-9833r364819_chk'
  tag severity: 'medium'
  tag gid: 'V-209582'
  tag rid: 'SV-209582r610285_rule'
  tag stig_id: 'AOSX-14-002017'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-9833r282229_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag legacy: ['SV-105039', 'V-95901']
  tag cci: ['CCI-000381', 'CCI-001774', 'CCI-001150', 'CCI-001153']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)', 'SC-15 a', 'SC-15 (1)']
end
