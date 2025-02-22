control 'SV-220488' do
  title 'The Cisco switch must be configured to implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.'
  desc 'check', 'Verify that FIPS mode is enabled as shown in the example below:

fips mode enable

Note: Cisco NX-OS software supports only SSH version 2 (SSHv2). Beginning in Cisco NX-OS Release 5.1, SSH runs in FIPS mode. Source: Cisco Nexus 7000 Series NX-OS Security Configuration Guide, Release 6.x

If the switch is not configured to implement cryptographic mechanisms to protect the confidentiality of remote maintenance sessions, this is a finding.'
  desc 'fix', 'Enable fips mode via the command fips mode enable.'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch NDM'
  tag check_id: 'C-22203r539185_chk'
  tag severity: 'medium'
  tag gid: 'V-220488'
  tag rid: 'SV-220488r604141_rule'
  tag stig_id: 'CISC-ND-000530'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-22192r539186_fix'
  tag 'documentable'
  tag legacy: ['SV-110625', 'V-101521']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
