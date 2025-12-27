control 'SV-215643' do
  title 'The Windows 2012 DNS Server must perform verification of the correct operation of security functions: upon system start-up and/or restart; upon command by a user with privileged access; and/or every 30 days.'
  desc 'Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. Without verification, security functions may not operate correctly and this failure may go unnoticed. 

Notifications provided by information systems include, for example, electronic alerts to system administrators, messages to local computer consoles, and/or hardware indications, such as lights.

The DNS server should perform self-tests, such as at server start-up, to confirm that its security functions are working properly.'
  desc 'check', 'This functionality should be performed by the Host Based Security System (HBSS), mandatory on all DoD systems.

Check to ensure McAfee HBSS is installed and fully operational on the Windows DNS Server.

If all required HBSS products are not installed and/or the installed products are not enabled, this is a finding.'
  desc 'fix', 'Follow the HBSS guidance to install all HBSS products to the Windows DNS Server.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16837r314404_chk'
  tag severity: 'medium'
  tag gid: 'V-215643'
  tag rid: 'SV-215643r561297_rule'
  tag stig_id: 'WDNS-SI-000006'
  tag gtitle: 'SRG-APP-000473-DNS-000072'
  tag fix_id: 'F-16835r314405_fix'
  tag 'documentable'
  tag legacy: ['SV-73143', 'V-58713']
  tag cci: ['CCI-000366', 'CCI-002775']
  tag nist: ['CM-6 b', 'SI-17']
end
