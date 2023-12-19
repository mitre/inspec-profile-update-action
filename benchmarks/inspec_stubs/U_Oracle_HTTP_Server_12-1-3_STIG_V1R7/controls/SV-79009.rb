control 'SV-79009' do
  title 'OHS must have the SSLFIPS directive enabled so SSL requests can be processed with client certificates only issued by DoD PKI or DoD-approved PKI Certification Authorities (CAs).'
  desc 'Non-DoD approved PKIs have not been evaluated to ensure that they have security controls and identity vetting procedures in place which are sufficient for DoD systems to rely on the identity asserted in the certificate. PKIs lacking sufficient security controls and identity vetting procedures risk being compromised and issuing certificates that enable adversaries to impersonate legitimate users.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for the "SSLFIPS" directive at the OHS server configuration scope.

3. Set the "SSLFIPS" directive to "On", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65271r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64519'
  tag rid: 'SV-79009r1_rule'
  tag stig_id: 'OH12-1X-000299'
  tag gtitle: 'SRG-APP-000427-WSR-000186'
  tag fix_id: 'F-70449r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
