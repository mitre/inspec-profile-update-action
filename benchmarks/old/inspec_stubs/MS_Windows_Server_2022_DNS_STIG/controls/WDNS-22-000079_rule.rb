control 'WDNS-22-000079_rule' do
  title 'The Windows 2022 DNS Server must verify the correct operation of security functions upon system startup and/or restart, upon command by a user with privileged access, and/or every 30 days.'
  desc 'Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes but is not limited to establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. Without verification, security functions may not operate correctly, and this failure may go unnoticed. 

Notifications provided by information systems include, for example, electronic alerts to system administrators, messages to local computer consoles, and/or hardware indications, such as lights.

The DNS server should perform self-tests, such as at server startup, to confirm that its security functions are working properly.'
  desc 'check', 'This functionality should be performed by an approved and properly configured DOD system monitoring solution. 

If all required DOD products are not installed and /or the installed productions are not enabled, this is a finding.'
  desc 'fix', 'Install an approved DOD system monitoring solution.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000079_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000079'
  tag rid: 'WDNS-22-000079_rule'
  tag stig_id: 'WDNS-22-000079'
  tag gtitle: 'SRG-APP-000473-DNS-000072'
  tag fix_id: 'F-WDNS-22-000079_fix'
  tag 'documentable'
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
