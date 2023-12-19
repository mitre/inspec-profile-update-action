control 'SV-233327' do
  title 'Forescout must be configured to apply dynamic ACLs that restrict the use of ports when non-entity endpoints are connected using MAC Authentication Bypass (MAB). This is required for compliance with C2C Step 4.'
  desc 'MAB is only one way of connecting non-entity endpoints, and can be defeated by spoofing the MAC address of an assumed authorized device. By adding the device to the MAR, the device can then gain access to the network.

NPE devices that can support PKI or an allowed authentication type must use PKI. MAB may be used for NPE that cannot support an approved device authentication. Non-entity endpoints include Internet of Things (IoT) devices, VoIP phone, and printer.'
  desc 'check', 'If DoD is not at C2C Step 4 or higher, this is not a finding.

Verify Forescout applies dynamic ACLs that restrict the use of ports when non-entity endpoints are connected using MAC Address Repository (MAR).

If the NAC does not apply dynamic ACLs that restrict the use of ports when non-entity endpoints are connected using MAR, this is a finding.'
  desc 'fix', 'Use the Forescout Administrator UI to configure the policy which identifies non-entity endpoints to complete a control action when a device is added to the MAR.

1. Log on to Forescout UI.
2. In the Policy tab, locate the Authentication and Authorization policy set.
3. Select a policy that identifies non-entity endpoints. Highlight the policy, then select "Edit".
4. From the Sub-Rules section, ensure that when a device is added to the MAR, the policy also applies one of the following actions:
-Access Port ACL
-Endpoint Address ACL
-WLAN Role'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36522r811402_chk'
  tag severity: 'medium'
  tag gid: 'V-233327'
  tag rid: 'SV-233327r856513_rule'
  tag stig_id: 'FORE-NC-000190'
  tag gtitle: 'SRG-NET-000343-NAC-001470'
  tag fix_id: 'F-36487r803471_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
