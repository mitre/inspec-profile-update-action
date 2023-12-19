control 'SV-79613' do
  title 'The DataPower Gateway must provide a logout capability for administrator-initiated communication sessions.'
  desc 'If an administrator cannot explicitly end a device management session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.'
  desc 'check', %q(Objects >> Device Management >> Web Management Service >> Idle timeout is set to 900 or less. 

Review the administrator's SSH Client Profile: Objects >> Crypto Configuration >> SSH Client Profile >> "Persistent Idle Timeout" is set to 900 or less. If it is not, this is a finding.)
  desc 'fix', 'Configure the DataPower Gateway Web Management service used by an administrator, to include an idle timeout (Objects >> Device Management >> Web Management Service): The time after which to invalidate idle administrator sessions. When invalidated, the web interface requires reauthentication.

For the SSH command-line interface used by an administrator, use the web interface (Objects >> Crypto Configuration >> SSH Client Profile) to configure an SSH Client Profile for the administrator user ID. Configure the "Persistent Idle Timeout" to 900 or less.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65751r2_chk'
  tag severity: 'medium'
  tag gid: 'V-65123'
  tag rid: 'SV-79613r2_rule'
  tag stig_id: 'WSDP-NM-000082'
  tag gtitle: 'SRG-APP-000296-NDM-000280'
  tag fix_id: 'F-71063r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
