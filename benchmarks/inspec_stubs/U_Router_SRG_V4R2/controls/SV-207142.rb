control 'SV-207142' do
  title 'The out-of-band management (OOBM) gateway router must be configured to forward only authorized management traffic to the Network Operations Center (NOC).'
  desc 'The OOBM network is an IP network used exclusively for the transport of OAM&P data from the network being managed to the OSS components located at the NOC. Its design provides connectivity to each managed network device, enabling network management traffic to flow between the managed network elements and the NOC. This allows the use of paths separate from those used by the managed network.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the network topology diagram to determine connectivity between the managed network and the NOC.

Review the OOBM gateway router configuration to validate the path that the management traffic traverses.

Verify that only management traffic is forwarded through the OOBM interface or IPsec tunnel.

If traffic other than authorized management traffic is permitted through the OOBM interface or IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure filters based on port, source IP address, and destination IP address to permit only authorized management traffic into IPsec tunnels or the OOBM interface used for forwarding management data.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7403r382409_chk'
  tag severity: 'medium'
  tag gid: 'V-207142'
  tag rid: 'SV-207142r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000010'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7403r382410_fix'
  tag 'documentable'
  tag legacy: ['V-78257', 'SV-92963']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
