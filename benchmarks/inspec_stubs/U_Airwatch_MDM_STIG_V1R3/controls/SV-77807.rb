control 'SV-77807' do
  title 'AirWatch MDM server versions that are no longer supported by the vendor for security updates must not be installed on a system.'
  desc 'AirWatch MDM server versions (6.5 and earlier versions) that are no longer supported by AirWatch by VMware for security updates are not  evaluated or updated for vulnerabilities, leaving them open to potential attack. Organizations must transition to a supported AirWatch MDM server version to ensure continued support.'
  desc 'check', 'On the AirWatch MDM server management console, determine the version of the AirWatch MDM server.

If the AirWatch MDM server version is 6.5 or earlier, this is a finding.'
  desc 'fix', 'Upgrade the AirWatch MDM server to a supported version.'
  impact 0.7
  ref 'DPMS Target AirWatch MDM 6.5'
  tag check_id: 'C-64051r1_chk'
  tag severity: 'high'
  tag gid: 'V-63317'
  tag rid: 'SV-77807r1_rule'
  tag stig_id: 'ARWA-04-000100'
  tag gtitle: 'Unsupported AirWatch MDM server applications'
  tag fix_id: 'F-69235r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
