control 'SV-85939' do
  title 'The CA API Gateway that provides intermediary services for TLS must be configured to comply with the required TLS settings in NIST SP 800-52.'
  desc 'SP 800-52 provides guidance on using the most secure version and configuration of the TLS/SSL protocol. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the Gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

SP 800-52 sets TLS version 1.1 as a minimum version; thus, all versions of SSL are not allowed (including for client negotiation) on either DoD-only or public-facing servers.

The CA API Gateway must be configured to use FIPS-140 cryptographic algorithms to meet the NIST SP 800-52 TLS settings.'
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Select "Manage Cluster-Wide Properties" from the "Tasks" menu. 

If the "security.fips.enabled" property is not listed or is set to false, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager.

Select "Manage Cluster-Wide Properties" from the "Tasks" menu. 

Click "Add" and select "security.fips.enabled" from the "Key:" drop-down list. 

Set the value to "true" and click "OK".'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71711r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71315'
  tag rid: 'SV-85939r1_rule'
  tag stig_id: 'CAGW-GW-000190'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag fix_id: 'F-77625r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
