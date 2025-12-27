control 'SV-251034' do
  title 'The Sentry must only allow incoming communications from organization-defined authorized sources routed to organization-defined authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic which poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Access control policies and access control lists implemented on devices that control the flow of network traffic (e.g., application level firewalls and Web content filters), ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the internet or CDS) must be kept separate.'
  desc 'check', 'Verify only approved network routes are added to the Sentry.

1. Log in to Sentry System Manager.
2. Go to Settings >> Network >> Routes.
3. Verify only approved network routes are configured.

If non-approved network routes are configured, this is a finding.'
  desc 'fix', 'Configure only approved network routes on the Sentry.

1. Log in to Sentry System Manager.
2. Go to Settings >> Routes.
3. Select any unauthorized network routes in the list and click "Delete".
4. Click "Add" to add approved routes.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54469r802322_chk'
  tag severity: 'medium'
  tag gid: 'V-251034'
  tag rid: 'SV-251034r802324_rule'
  tag stig_id: 'MOIS-AL-001000'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-54423r802323_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
