control 'SV-251360' do
  title 'Network Address Translation (NAT) and private IP address space must not be deployed within the SIPRNet enclave.'
  desc "The DoD has an enterprise level security-focused configuration management (SecCM) requirement to support end-to-end monitoring of SIPRNet, as a National Security System (NSS). The use of NAT and private IP address space inhibits the view of specialized DISN enterprise tools in tracking client level enclave to enclave traffic, monitoring client use of enterprise level application services, and detecting anomalies and potential malicious attacks in SIPRNet client application traffic flows. Enclave nodes that communicate outside the organization's enclave to other SIPRNet enclaves or enterprise services cannot use NATd private addresses via an enclave proxy without the permission of the SIPRNet DISN Authorizing Official, the DISA AO."
  desc 'check', "Review network diagrams, enterprise sensor reports, and network scans submitted to the Connection Approval Office. Determine that only global IP addresses assigned by the NIC are in use within the organization's SIPRNet enclave.

NOTE: This requirement also applies to IPv6 ULA addresses. The IPv6 ULA is unauthorized on SIPR without approval.

Determine whether NAT and unauthorized IP address space is in use in the organization's SIPRNet enclave.

Exceptions to this requirement are listed below:
1. Closed classified networks logically transiting SIPRNet for enclave-to-enclave VPN transport only.
2. Out-of-Band management networks, where the NATd nodes do not access SIPRNet base enterprise services.
3. Thin client deployments where the hosting thin client server serves as the SIPRNet access point for its thin clients and that the organization maintains detailed thin client service usage audit logs.
4. Valid operational mission need or implementation constraints.

All exceptions must have approval by the SIPRNet DISN accreditation official, DISA AO.

If NAT and unauthorized IP address space is in use on the organization's SIPRNet infrastructure, this is a finding."
  desc 'fix', "Remove the NAT configurations and private address space from the organization's SIPRNet enclave.  Configure the SIPRNet enclave with SSC authorized .smil.mil or .sgov.gov addresses. If NAT or private address space is required, as per one of the stated exceptions or for valid mission requirements, then submit a detailed approval request to use private addressing through the DSAWG Secretariat to the DISN accreditation official, DISA AO."
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54795r808529_chk'
  tag severity: 'medium'
  tag gid: 'V-251360'
  tag rid: 'SV-251360r808530_rule'
  tag stig_id: 'NET0185'
  tag gtitle: 'NET0185'
  tag fix_id: 'F-54748r806034_fix'
  tag 'documentable'
  tag legacy: ['V-31637', 'SV-41924']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
