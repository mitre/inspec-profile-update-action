control 'SV-81143' do
  title 'If IDPS inspection is performed separately from the Juniper SRX Services Gateway VPN device, the VPN must route sessions to an IDPS for inspection.'
  desc 'Remote access devices, such as those providing remote access to network devices and information systems, which lack automated, capabilities increase risk and makes remote user access management difficult at best.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. 

Automated monitoring of remote access sessions allows organizations to detect cyber attacks and also ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities, from a variety of information system components (e.g., servers, workstations, notebook computers, smart phones, and tablets).'
  desc 'check', 'Verify a security zone is configured for the VPN Internet Key Exchange (IKE) service.

[edit]
show security zones

If a security zone is not configured for the IKE traffic, this is a finding.'
  desc 'fix', 'Allow IKE as a host-inbound service within the security zone associated with the IKE gateway’s external interface configuration. Assuming the use of ge-0/0/0, which is associated with the “untrust” zone, the following is an example of zone configuration.

[edit]
set security zones security-zone untrust host-inbound-traffic system-services ike'
  impact 0.5
  ref 'DPMS Target Juniper SRX SG VPN'
  tag check_id: 'C-67279r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66653'
  tag rid: 'SV-81143r1_rule'
  tag stig_id: 'JUSX-VN-000011'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-72729r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
