control 'SV-91151' do
  title 'Kona Site Defender must only allow incoming communications from organization-defined authorized sources routed to organization-defined authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic which poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Access control policies and access control lists implemented on devices that control the flow of network traffic (e.g., application level firewalls and Web content filters), ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet or CDS) must be kept separate.'
  desc 'check', 'Confirm Kona Site Defender is configured to connect to the correct origin server:

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click the "Select Group or Property" button.
3. Select the configuration that is being reviewed.
4. Under the "Active Production" section, click on the active version.
5. In the "Origin Server" section, verify the "Origin Server Hostname" is valid.

If the "Origin Server Hostname" is not valid, then this is a finding.'
  desc 'fix', 'Configure Kona Site Defender to connect to the correct origin server:

1. Log in to the Akamai Luna Portal (Caution-https://control.akamai.com).
2. Click the "Select Group or Property" button.
3. Select the configuration that is being reviewed.
4. Under the "Active Production" section, click on the active version.
5. Click the "Edit" button (if not already selected).
6. In the "Origin Server" section, change the "Origin Server Hostname" to the correct hostname.
7. Click the "Save" button.
8. Activate the configuration by clicking the "Activate" tab and the activate buttons for the proper network (either staging or production).'
  impact 0.5
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76115r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76455'
  tag rid: 'SV-91151r1_rule'
  tag stig_id: 'AKSD-WF-000055'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-83133r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
