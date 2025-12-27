control 'SV-257198' do
  title 'The macOS system must cover or disable the built-in or attached camera when not in use.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Failing to disconnect from collaborative computing devices (i.e., cameras) can result in subsequent compromises of organizational information. Providing easy methods to physically disconnect from such devices after a collaborative computing session helps to ensure that participants carry out the disconnect activity without having to go through complex and tedious procedures.

'
  desc 'check', 'If the device or operating system does not have a camera installed, this requirement is not applicable.

This requirement is not applicable to mobile devices (smartphones and tablets), where the use of the camera is a local AO decision.

This requirement is not applicable to dedicated VTC suites located in approved VTC locations that are centrally managed.

For an external camera, if there is not a method for the operator to manually disconnect camera at the end of collaborative computing sessions, this is a finding.

For a built-in camera, the camera must be protected by a camera cover (e.g., laptop camera cover slide) when not in use. If the built-in camera is not protected with a camera cover, or is not physically disabled, this is a finding.

If the camera is not disconnected, covered, or physically disabled, the following configuration is required:

/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep "allowCamera"

allowCamera = 0;

If the result is "allowCamera = 1" and the collaborative computing device has not been authorized for use, this is a finding.'
  desc 'fix', 'Configure the macOS system to disable the built-in camera by installing the "Restrictions Policy" configuration profile.'
  impact 0.5
  ref 'DPMS Target Apple macOS 13'
  tag check_id: 'C-60883r905225_chk'
  tag severity: 'medium'
  tag gid: 'V-257198'
  tag rid: 'SV-257198r905227_rule'
  tag stig_id: 'APPL-13-002017'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-60824r905226_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000370-GPOS-00155']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001774']
  tag nist: ['CM-7 a', 'CM-7 (5) (b)']
end
