control 'SV-82589' do
  title 'The A10 Networks ADC must use DoD-approved PKI rather than proprietary or self-signed device certificates.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Review the device configuration.

This can be checked using the GUI:
Log on to the device and navigate to Config >> System >> Settings >> Web Certificate.

In the certificate pane, view the issuer information.

If each certificate is not issued by an approved service provider, this is a finding.'
  desc 'fix', 'Only import public key certificates from an appropriate certificate policy through an approved service provider.

Use the commands "import ssl-cert" and "import ssl-key" or "slb ssl-load" to import SSL certificates and keys.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68659r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68099'
  tag rid: 'SV-82589r1_rule'
  tag stig_id: 'AADC-NM-000142'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-74213r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001159']
  tag nist: ['CM-6 b', 'SC-17 a']
end
