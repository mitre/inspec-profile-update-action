control 'SV-234538' do
  title 'Before establishing a connection to any endpoint device being managed, the UEM server must establish a trusted path between the server and endpoint that provides assured identification of the end point using a bidirectional authentication mechanism configured with a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to authenticate with the device.'
  desc 'Without device-to-device authentication, communications with malicious devices may be established. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk. Currently, DoD requires the use of AES for bidirectional authentication since it is the only FIPS-validated AES cipher block algorithm. 

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.

A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network; the internet). A remote connection is any connection with a device communicating through an external network (e.g., the internet).

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to apply the requirement only to those limited number (and type) of devices that truly need to support this capability. 

Satisfies:FIA_X509_EXT.1(1), FIA_ENR_EXT.1.1'
  desc 'check', 'Verify the UEM server establishes a trusted path between the server and endpoint that provides assured identification of the end point using a bidirectional authentication mechanism configured with a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to authenticate with the device before establishing a connection to any endpoint device being managed. 

If the UEM server does not establish a trusted path between the server and endpoint that provides assured identification of the end point using a bidirectional authentication mechanism configured with a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to authenticate with the device before establishing a connection to any endpoint device being managed, this is a finding.'
  desc 'fix', 'Configure the UEM server to establish a trusted path between the server and endpoint that provides assured identification of the end point using a bidirectional authentication mechanism configured with a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to authenticate with the device before establishing a connection to any endpoint device being managed.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37723r851610_chk'
  tag severity: 'high'
  tag gid: 'V-234538'
  tag rid: 'SV-234538r879768_rule'
  tag stig_id: 'SRG-APP-000395-UEM-000266'
  tag gtitle: 'SRG-APP-000395'
  tag fix_id: 'F-37688r878109_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
