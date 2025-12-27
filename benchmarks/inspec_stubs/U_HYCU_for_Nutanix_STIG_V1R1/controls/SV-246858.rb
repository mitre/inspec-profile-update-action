control 'SV-246858' do
  title 'The network device must generate unique session identifiers using a FIPS 140-2 approved random number generator.'
  desc 'Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

This requirement is applicable to devices that use a web interface for device management.'
  desc 'check', %q(When FIPS mode is enabled, HYCU will use FIPS-compliant behavior. Validation of FIPS status can be done using the following commands:
'cat /proc/sys/crypto/fips_enabled' 

If command output does not show "1", this is a finding.

'fips-mode-setup --check'

If command output does not show "FIPS mode is enabled", this is a finding.

'update-crypto-policies --show'

If command output does not show "FIPS", this is a finding.)
  desc 'fix', 'Stop the HYCU web server: 
sudo systemctl stop grizzly.service

Enable FIPS-compliant mode: 
sudo /opt/grizzly/bin/enable_fips.sh

Reboot the HYCU virtual machines:
shutdown -r now'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50290r768236_chk'
  tag severity: 'medium'
  tag gid: 'V-246858'
  tag rid: 'SV-246858r768238_rule'
  tag stig_id: 'HYCU-SC-000002'
  tag gtitle: 'SRG-APP-000224-NDM-000270'
  tag fix_id: 'F-50244r768237_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
