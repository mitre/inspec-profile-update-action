control 'SV-220384' do
  title 'MarkLogic Server must disable network functions, ports, protocols, and services deemed by the organization to be nonsecure, in accordance with Ports, Protocols, and Services Management (PPSM) guidance.'
  desc 'Use of nonsecure network functions, ports, protocols, and services exposes the system to avoidable threats.'
  desc 'check', 'Review the network functions, ports, protocols, and services supported by MarkLogic for any that are prohibited by the PPSM guidance.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the App Servers icon on the left tree menu.
4. Inspect the Summary screen for the Type/Port/ and SSL configuration.
5. If any of the App Servers uses a protocol or port prohibited by the PPSM guidance, this is a finding.'
  desc 'fix', 'Disable each prohibited network function, port, protocol, or service in MarkLogic.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Groups icon.
2. Click the group in which the configuration to be checked resides (e.g., Default).
3. Click the App Servers icon on the left tree menu.
4. For any App Server that uses a prohibited port or protocol either disable the App Server or reconfigure to be compliant with the PPSM.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22099r401603_chk'
  tag severity: 'medium'
  tag gid: 'V-220384'
  tag rid: 'SV-220384r855489_rule'
  tag stig_id: 'ML09-00-008000'
  tag gtitle: 'SRG-APP-000383-DB-000364'
  tag fix_id: 'F-22088r401604_fix'
  tag 'documentable'
  tag legacy: ['SV-110117', 'V-101013']
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
end
