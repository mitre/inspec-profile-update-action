control 'SV-228841' do
  title 'The Palo Alto Networks security platform that provides intermediary services for TLS must validate certificates used for TLS functions by performing RFC 5280-compliant certification path validation.'
  desc "A certificate's certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate.

Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.

The Palo Alto Networks security platform can be configured to use Open Certificate Status Protocol (OCSP) and/or certificate revocation lists (CRLs) to verify the revocation status of certificates and the device itself can be configured as an OCSP responder."
  desc 'check', 'If the Palo Alto Networks security platform does not provide intermediary services for TLS or application protocols that use TLS (e.g., HTTPS), this is not applicable.
Go to Device >> Certificate Management >> OCSP Responder
If no OCSP Responder is configured, this is a finding.
Go to Device >> Setup >> Management
In the "Management Interface Settings" pane, if "HTTP OCSP" is not listed under "Services", this is a finding.'
  desc 'fix', 'To configure the Palo Alto Networks security platform to use an OCSP responder:
Go to Device >> Certificate Management >> OCSP Responder
Select "Add".
In the "OCSP Responder" window, enter the host name or IP address of the OCSP responder.

Note: If the firewall itself is configured as an OCSP responder, the host name must resolve to an IP address in the interface that the firewall uses for OCSP services.

To enable OCSP communication on the firewall:
Go to Device >> Setup >> Management
In the "Management Interface Settings" pane, select the "Edit" icon.
In the "Management Interface Settings" box, under "Services" check HTTP OCSP to enable it.
Select "OK"

Optionally, to configure the device itself as an OCSP responder, add an Interface Management Profile to the interface used for OCSP services.

Go to Network >> Network Profiles >> Interface Management
Select "Add" to create a new profile or click the name of an existing profile.
In the "Interface Management Profiles" window, under "Permitted Services", check HTTP OCSP.
Select "OK".

Go to Network >> Interfaces
Select the name of the interface that the firewall will use for OCSP services.

Note: When the  device itself as an OCSP responder, the OCSP Host Name must resolve to an IP address in this interface.

In the "Interface" window, under Other Info, in the "Management Profile" field, select the configured Management Profile.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31076r513818_chk'
  tag severity: 'medium'
  tag gid: 'V-228841'
  tag rid: 'SV-228841r557387_rule'
  tag stig_id: 'PANW-AG-000044'
  tag gtitle: 'SRG-NET-000164-ALG-000100'
  tag fix_id: 'F-31053r513819_fix'
  tag 'documentable'
  tag legacy: ['SV-77055', 'V-62565']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
