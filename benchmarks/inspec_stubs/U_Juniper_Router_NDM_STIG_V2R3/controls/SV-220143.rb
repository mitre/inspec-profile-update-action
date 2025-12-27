control 'SV-220143' do
  title 'The Juniper router must be running a Junos release that is currently supported by Juniper Networks.'
  desc 'Network devices running an unsupported operating system lack current security fixes required to mitigate the risks associated with recent vulnerabilities. Running a supported release also enables operations to maintain a stable and reliable network provided by improved quality of service and security features.'
  desc 'check', 'Verify that the router is in compliance with this requirement by having the router administrator enter the following command: show version

End of support dates for all Junos releases can be found at the URL listed below.
https://support.juniper.net/support/eol/software/junos/

If the Juniper router is not running a supported Junos release, this is a finding.'
  desc 'fix', 'Upgrade the Juniper router to a supported release.'
  impact 0.7
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-21858r388906_chk'
  tag severity: 'high'
  tag gid: 'V-220143'
  tag rid: 'SV-220143r879887_rule'
  tag stig_id: 'JUNI-ND-001470'
  tag gtitle: 'SRG-APP-000516-NDM-000351'
  tag fix_id: 'F-21850r388907_fix'
  tag 'documentable'
  tag legacy: ['SV-101301', 'V-91201']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
