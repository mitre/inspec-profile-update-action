control 'SV-234603' do
  title 'The UEM server must remove old software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.

If the update is due to a security issue with the old version of the app, the old version is not reinstalled. If rollback files are used by the server, they must be stored so as to not be easily accessible to the production system, or cannot be accidentally installed on the operational system, and then must be deleted after a short period of time defined by the organization.'
  desc 'check', 'Verify the UEM server removes old software components after updated versions have been installed.

If the UEM server does not remove old software components after updated versions have been installed, this is a finding.'
  desc 'fix', 'Configure the UEM server to remove old software components after updated versions have been installed.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37788r615443_chk'
  tag severity: 'medium'
  tag gid: 'V-234603'
  tag rid: 'SV-234603r617355_rule'
  tag stig_id: 'SRG-APP-000454-UEM-000328'
  tag gtitle: 'SRG-APP-000454'
  tag fix_id: 'F-37753r615444_fix'
  tag 'documentable'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
end
