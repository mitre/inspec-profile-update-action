control 'SV-234701' do
  title 'Chrome must be configured to allow only TLS.'
  desc 'If this policy is not configured then Google Chrome uses a default minimum version, which is TLS 1.0. Otherwise, it may be set to one of the following values: "tls1", "tls1.1" or "tls1.2".
When set, Google Chrome will not use SSL/TLS versions less than the specified version. An unrecognized value will be ignored.
"tls1" = TLS 1.0
"tls1.1" = TLS 1.1
"tls1.2" = TLS 1.2'
  desc 'check', 'Universal method: 
 1. In the omnibox (address bar) type chrome://policy
 2. If "SSLVersionMin" is not displayed under the "Policy Name" column or it is not set to "tls1.2", this is a finding.
Windows method:
 1. Start regedit
 2. Navigate to HKLM\\Software\\Policies\\Google\\Chrome\\
 3. If the "SSLVersionMin" value name does not exist or its value data is not set to "tls1.2", this is a finding.'
  desc 'fix', 'Windows group policy:
 1. Open the “group policy editor” tool with gpedit.msc.
 2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Google\\Google Chrome\\
 Policy Name: Minimum SSL version enabled
 Policy State: Enabled
 Policy Value: TLS 1.2'
  impact 0.7
  ref 'DPMS Target Google Chrome Current Windows'
  tag check_id: 'C-37887r622475_chk'
  tag severity: 'high'
  tag gid: 'V-234701'
  tag rid: 'SV-234701r615937_rule'
  tag stig_id: 'DTBC-0056'
  tag gtitle: 'SRG-APP-000416'
  tag fix_id: 'F-37849r622476_fix'
  tag 'documentable'
  tag legacy: ['V-81583']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
