control 'SV-233327' do
  title 'Forescout must be configured to apply dynamic ACLs that restrict the use of ports when non-entity endpoints are connected using MAC Authentication Bypass (MAB).'
  desc 'MAB is only one way of connecting non-entity endpoints, and can be defeated by spoofing the MAC address of an assumed authorized device. By adding the device to the MAB, the device can then gain access to the network.

NPE devices that can support PKI or an allowed authentication type must use PKI. MAB may be used for NPE that cannot support an approved device authentication. Non-entity endpoints include Internet of Things (IoT) devices, VoIP phone, and printer.'
  desc 'check', 'Verify Forescout applies dynamic ACLs that restrict the use of ports when non-entity endpoints are connected using MAC Address Repository (MAR).

If the NAC does not apply dynamic ACLs that restrict the use of ports when non-entity endpoints are connected using MAR, this is a finding.'
  desc 'fix', 'Log on to Forescout UI.

1. In the Policy tab, locate the Authentication and Authorization policy set.
2. Select a policy that identifies non-entity endpoints. Highlight the policy, then select "Edit".
3. From the Sub-Rules section, ensure that when a device is added to the MAR, the policy also applies one of the following actions:
-Access Port ACL
-Endpoint Address ACL
-WLAN Role'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36522r605684_chk'
  tag severity: 'medium'
  tag gid: 'V-233327'
  tag rid: 'SV-233327r611394_rule'
  tag stig_id: 'FORE-NC-000190'
  tag gtitle: 'SRG-NET-000343-NAC-001470'
  tag fix_id: 'F-36487r605685_fix'
  tag 'documentable'
  tag cci: ['CCI-001958']
  tag nist: ['IA-3']
end
