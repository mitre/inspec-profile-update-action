control 'SV-254221' do
  title 'Nutanix AOS must prohibit the use of cached authenticators.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.'
  desc 'check', 'Confirm Nutanix AOS is not configured to allow cached credentials via the System Security Session Daemon (SSSD).

$ service sssd status

If the sssd service is installed or active, this is a finding.'
  desc 'fix', 'If the SSSD service is installed, the Controller VM must be reinstalled.'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57706r846749_chk'
  tag severity: 'medium'
  tag gid: 'V-254221'
  tag rid: 'SV-254221r846751_rule'
  tag stig_id: 'NUTX-OS-001370'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag fix_id: 'F-57657r846750_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
