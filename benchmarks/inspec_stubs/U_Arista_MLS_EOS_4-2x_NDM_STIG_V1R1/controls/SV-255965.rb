control 'SV-255965' do
  title 'The Arista network device must obtain its public key certificates from an appropriate certificate policy through an approved service provider.'
  desc 'For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice.'
  desc 'check', 'Determine if the Arista network device obtains public key certificates from an appropriate certificate policy through an approved service provider.

Note: This check is Not Applicable if not using any PKI certificates.

Verify the DOD PKI certificates are copied to /certificate directory on the switch as outlined in the Arista Military Deployment Guide and configured as in the section "Configuring RSA SecureID with OTP Management".

  switch# #dir certificate:
Directory of certificate:/
       -rw-        2025           Apr 30 17:34  ARISTA_ROOT_CA.crt
       -rw-        2110           Apr 30 17:34  ARISTA_SIGNING_CA.crt
       -rw-        2015           Apr 30 17:35  Arista-CCS-720XP-48Y6.pem
       -rw-        2020           Apr 30 17:35  DOD_JITC_Root_CA_3__0x01__DOD_JITC_Root_CA_3.cer
       -rw-        2125           Apr 30 17:35  CA-60.cer
!

Verify the provider of the certificate is a DOD-approved certificate authority.

If the Arista network device does not obtain its public key certificates from an appropriate certificate policy through an approved service provider, this is a finding.'
  desc 'fix', %q(Configure the Arista network device to obtain its public key certificates from an appropriate certificate policy through an approved service provider.

Step 1: Configure the Arista network device by following the steps outlined in the Arista Military Unique Deployment Guide to generate the DOD PKI certificate signing request [switch.csr] for submission to DOD PKI CA. Example configuration:

switch#security pki certificate generate signing-request key rsa1.key
Common Name for use in subject: 192.168.25.26
Two-Letter Country Code for use in subject: US
State for use in subject: AZ
Locality Name for use in subject: Ft Huachuca
Organization Name for use in subject: CONTRACTOR,PKI,DOD
Organization Unit Name for use in subject: U.S. GOVERNMENT
Email address for use in subject: 
IP addresses (space separated) for use in subject-alternative-name: 192.168.25.26
DNS names (space separated) for use in subject-alternative-name: 
Email addresses (space separated) for use in subject-alternative-name: 
-----BEGIN CERTIFICATE REQUEST-----
MIIC6DCCAdACAQAwgYAxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJBWjEUMBIGA1UE
BwwLRnQgSHVhY2h1Y2ExGzAZBgNVBAoMEkNPTlRSQUNUT1IsUEtJLERvRDEYMBYG
A1UECwwPVS5TLiBHT1ZFUk5NRU5UMRcwFQYDVQQDDA4xOTIuMTY4LjI0MC4yMzCC
i7TGBvhm5PTbfAzBma8/hSlsBGJ0qnOteb1Zaw== <Abbreviated Output Due to Size>
-----END CERTIFICATE REQUEST-----

Step 2: Once the DOD PKI signed certificates are received, CA Root Certificate and Intermediate Certificates obtained from CA must be uploaded onto the Arista network device directory of /certificate: The certificate's transfer can be accomplished by SCP or USB. The detail configuration can be found in the Arista Military Unique Deployment Guide in the section "Configuring RSA SecureID with OTP Management". 

The following commands copy the certificates using device USB1: to directory of the certificate:

switch#copy usb1:Arista-23.pem certificate:
Copy completed successfully.
switch#copy usb1: CA-60.crt certificate:
Copy completed successfully.
switch#copy usb1: DODDISASWCA_60.crt certificate:
Copy completed successfully.
!
The following commands verify all three certificates are correctly copied to the certificate directory: 

switch#directory certificate
switch#dir certificate:
Directory of certificate:/
       -rw-        2025           Aug 11 10:52  CA-60.crt
       -rw-        2110           Aug 11 10:52  ARISTA_SIGNING_CA.crt
       -rw-        1724            Aug 9 14:35  DODDISASWCA_60.crt
       -rw-        1722           Aug 12 09:38  arista-b64.cer
       -rw-        1696           Aug 12 14:35  Arista-23.pem
       -rw-        1696           Aug 12 14:36  intCert.pem
!

The following commands configure the SSL-profile using the PKI certificates on the switch with the RSA SecureID server and trust chain:

switch(config)#management security
switch(config-mgmt-security)#ssl profile RSA01
switch(config-mgmt-sec-ssl-profile-RSA01)#tls versions 1.2
switch(config-mgmt-sec-ssl-profile-RSA01)#certificate Arista-23.pem key rsa1.key
switch(config-mgmt-sec-ssl-profile-RSA01)#trust certificate Arista-23.pem
switch(config-mgmt-sec-ssl-profile-RSA01)#trust certificate DODDISASWCA_60.crt
switch(config-mgmt-sec-ssl-profile-RSA01)#chain certificate CA-60.cer
switch(config-mgmt-sec-ssl-profile-RSA01)#show active
management security
   ssl profile RSA01
      tls versions 1.2
      certificate Arista-23.pem.pem key rsa1.key
      trust certificate certificate Arista-23.pem
      trust certificate CA-60.cer
      trust certificate DODDISASWCA_60.crt
      chain certificate CA-60.crt
radius-server tls ssl-profile RSA01
!

Step 3: Configure the switch RadSec Proxy server and RSA SecureID server IP address and RADIUS attribute configuration for ssl-profile RSA01.

switch(config)#radius-server tls ssl-profile RSA01
switch(config)#radius-server host 192.168.16.102 key 7 09595D080D0C1453
switch(config)#radius-server host 192.168.16.55 key 7 120C161606020F45
switch(config)#radius-server host 192.168.16.55 tls
switch(config)#aaa group server radius RADsecProxy
   server 192.168.16.55 tls
!

Step 4: Configure the AAA authentication and authorization parameters for SSL-profile and RadSec Proxy Server.

switch(config)#no aaa root
switch(config)#aaa authorization policy local default-role aristaadmin
switch(config)#logging level AAA informational
switch(config)#aaa group server radius RADsecProxy
   server 192.168.16.55 tls
switch(config)#aaa group server radius TIC1
   server 192.168.16.103
switch(config)#aaa authentication login default local group RADsecProxy
switch(config)#aaa authentication login console local
switch(config)#aaa authentication policy on-success log
switch(config)#aaa authentication policy on-failure log
switch(config)#aaa authorization exec default local group RADsecProxy
switch(config)#aaa authorization commands all default local
switch(config)#aaa accounting commands all default start-stop logging group radius
switch(config)#write
!

Step 5: Verify the AAA configuration to ensure all parameters from the previous step are accurate with the following command:

switch(config)#show running-config | section aaa
no aaa root
aaa authorization policy local default-role aristaadmin
logging level AAA informational
aaa group server radius RADsecProxy
   server 192.168.16.55 tls
aaa group server radius TIC1
   server 192.168.16.103
aaa authentication login default local group RADsecProxy
aaa authentication login console local
aaa authentication policy on-success log
aaa authentication policy on-failure log
aaa authorization exec default local group RADsecProxy
aaa authorization commands all default local
aaa accounting commands all default start-stop logging group radius
!
switch#show aaa methods authentication 
Authentication method lists for LOGIN:
  name=default methods=local, group RADsecProxy
  name=login methods=local
Authentication method list for ENABLE:
  name=default methods=local
Authentication method list for DOT1X:
  name=default methods=
!
switch##sh radius
RADIUS server             : 192.168.16.45, authentication port 1812, accounting port 1813 
             Messages sent:          10
         Messages received:      10
         Requests accepted:      9
         Requests rejected:        1
          Requests timeout:       0
    Requests retransmitted:  0
             Bad responses:           0
         Connection errors:        0
                DNS errors:              0
      CoA request received:     0
       DM request received:    0
              CoA ack sent:            0
               DM ack sent:           0
              CoA Nak sent:           0
               DM Nak sent:          0

RADIUS server-group: RSA1
     0: 192.168.16.45, authentication port 1812, accounting port 1813 

RADIUS server-group: TIC1
     0: 192.168.16.103, authentication port 1812, accounting port 1813 
Last time counters were cleared: never
!
trust certificate Arista-23.pem
switch#(config-mgmt-sec-ssl-profile-RSA1)#Aug 24 15:56:41 switch SuperServer: %SECURITY-3-SSL_PROFILE_VALID: SSL profile 'RSA01' is valid.)
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59641r882235_chk'
  tag severity: 'medium'
  tag gid: 'V-255965'
  tag rid: 'SV-255965r882237_rule'
  tag stig_id: 'ARST-ND-000840'
  tag gtitle: 'SRG-APP-000516-NDM-000344'
  tag fix_id: 'F-59584r882236_fix'
  tag 'documentable'
  tag cci: ['CCI-001159']
  tag nist: ['SC-17 a']
end
