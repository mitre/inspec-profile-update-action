control 'SV-241788' do
  title 'HTTPAPI Server version must be removed from the HTTP Response Header information.'
  desc 'HTTP Response Headers contain information that could enable an attacker to gain access to an information system. Failure to prevent the sending of certain HTTP Response Header information to remote requesters exposes internal configuration information to potential attackers.'
  desc 'check', 'Open Registry Editor.

Navigate to “HKLM\\System\\CurrentControlSet\\Services\\HTTP\\Parameters”

Verify “DisableServerHeader” is set to “1”.

If REG_DWORD DisableServerHeader is not set to 1, this is a finding.

If the System Administrator can show that Server Version information has been removed via other means, such as using a rewrite outbound rule, this is not a finding.'
  desc 'fix', 'Navigate to “HKLM\\System\\CurrentControlSet\\Services\\HTTP\\Parameters”.

Create REG_DWORD “DisableServerHeader” and set it to “1”.

Note: This can be performed multiple ways, this is an example.'
  impact 0.3
  ref 'DPMS Target Microsoft IIS 10.0 Server'
  tag check_id: 'C-45064r766899_chk'
  tag severity: 'low'
  tag gid: 'V-241788'
  tag rid: 'SV-241788r766901_rule'
  tag stig_id: 'IIST-SV-000210'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-45023r766900_fix'
  tag 'documentable'
  tag legacy: ['SV-54431', 'V-41854']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
