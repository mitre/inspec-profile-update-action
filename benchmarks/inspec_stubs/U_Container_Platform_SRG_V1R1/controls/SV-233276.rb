control 'SV-233276' do
  title 'The container platform must prohibit communication using TLS versions 1.0 and 1.1, and SSL 2.0 and 3.0.'
  desc 'The container platform and its components will prohibit the use of SSL and unauthorized versions of TLS protocols to properly secure communication.

The use of unsupported protocol exposes vulnerabilities to the container platform by rogue traffic interceptions, man-in-the middle-attacks, and impersonation of users or services from the container platform runtime, registry, and keystore.

The container platform and its components will adhere to NIST 800-52R2.'
  desc 'check', 'Review the container platform configuration to determine if TLS versions 1.0 and 1.1, SSL 2.0 and 3.0 are prohibited for communication. 

If communication using TLS versions 1.0 and 1.1, SSL 2.0 and 3.0 is permitted, this is a finding.'
  desc 'fix', 'Configure the container platform to prohibit communication using TLS versions 1.0 and 1.1, SSL 2.0 and 3.0.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36212r599464_chk'
  tag severity: 'medium'
  tag gid: 'V-233276'
  tag rid: 'SV-233276r599509_rule'
  tag stig_id: 'SRG-APP-000560-CTR-001340'
  tag gtitle: 'SRG-APP-000560'
  tag fix_id: 'F-36180r599465_fix'
  tag 'documentable'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
