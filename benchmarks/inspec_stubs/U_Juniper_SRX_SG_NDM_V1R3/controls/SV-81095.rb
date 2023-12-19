control 'SV-81095' do
  title 'For nonlocal maintenance sessions, the Juniper SRX Services Gateway must explicitly deny the use of J-Web.'
  desc 'If unsecured functions (lacking FIPS-validated cryptographic mechanisms) are used for management sessions, the contents of those sessions are susceptible to manipulation, potentially allowing alteration and hijacking.

J-Web (configured using the system services web-management option) does not meet the DoD requirement for management tools. It also does not work with all Juniper SRX hardware. By default, the web interface is disabled; however, it is easily enabled.'
  desc 'check', 'Verify web-management is not enabled.

[edit]
show system services web-management

If a stanza exists that configures web-management service options, this is a finding.'
  desc 'fix', 'Remove the web-management service.

[edit]
delete system services web-management'
  impact 0.7
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67231r1_chk'
  tag severity: 'high'
  tag gid: 'V-66605'
  tag rid: 'SV-81095r1_rule'
  tag stig_id: 'JUSX-DM-000167'
  tag gtitle: 'SRG-APP-000142-NDM-000245'
  tag fix_id: 'F-72681r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
