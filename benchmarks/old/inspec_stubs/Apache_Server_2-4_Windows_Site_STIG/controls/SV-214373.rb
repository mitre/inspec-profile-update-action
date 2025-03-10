control 'SV-214373' do
  title 'Anonymous user access to the Apache web server application directories must be prohibited.'
  desc 'To properly monitor the changes to the web server and the hosted applications, logging must be enabled. Along with logging being enabled, each record must properly contain the changes made and the names of those who made the changes.

Allowing anonymous users the capability to change the web server or the hosted application will not generate proper log information that can then be used for forensic reporting in the case of a security issue. Allowing anonymous users to make changes will also grant change capabilities to anybody without forcing a user to authenticate before the changes can be made.

'
  desc 'check', 'Obtain a list of the user accounts for the system, noting the privileges for each account.

Verify with the System Administrator (SA) or the Information System Security Officer (ISSO) that all privileged accounts are mission essential and documented.

Verify with the SA or the ISSO that all non-administrator access to shell scripts and operating system functions are mission essential and documented.

If undocumented privileged accounts are present, this is a finding.

If undocumented access to shell scripts or operating system functions is present, this is a finding.'
  desc 'fix', 'Ensure non-administrators are not allowed access to the directory tree, the shell, or other operating system functions and utilities.'
  impact 0.7
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15584r277860_chk'
  tag severity: 'high'
  tag gid: 'V-214373'
  tag rid: 'SV-214373r397711_rule'
  tag stig_id: 'AS24-W2-000440'
  tag gtitle: 'SRG-APP-000211-WSR-000031'
  tag fix_id: 'F-15582r277861_fix'
  tag satisfies: ['SRG-APP-000211-WSR-000031', 'SRG-APP-000380-WSR-000072']
  tag 'documentable'
  tag legacy: ['SV-102617', 'V-92529']
  tag cci: ['CCI-001082', 'CCI-001813']
  tag nist: ['SC-2', 'CM-5 (1) (a)']
end
