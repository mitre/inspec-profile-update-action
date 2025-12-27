control 'SV-237339' do
  title 'The ArcGIS Server keystores must only contain certificates of PKI established certificate authorities for verification of protected sessions.'
  desc 'Untrusted Certificate Authorities (CA) can issue certificates, but they may be issued by organizations or individuals that seek to compromise DoD systems or by organizations with insufficient security controls. If the CA used for verifying the certificate is not a DoD-approved CA, trust of this CA has not been established.

The DoD will only accept PKI certificates obtained from a DoD-approved internal or external certificate authority. Reliance on CAs for the establishment of secure sessions includes, for example, the use of SSL/TLS certificates. 

This requirement focuses on communications protection for the application session rather than for the network packet.

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA).'
  desc 'check', 'Review the ArcGIS Server configuration to ensure the application only allows the use of DoD PKI established certificate authorities for verification of the establishment of protected sessions. Substitute the target environment’s values for [bracketed] variables.

1. Use a Java-compatible tool to access the java keystore at [C:\\Program Files\\ArcGIS\\Server\\framework\\runtime\\jre\\lib\\security\\cacerts].

The password for the keystore is "changeit".

Verify that the Java Keystore [C:\\Program Files\\ArcGIS\\Server\\framework\\runtime\\jre\\lib\\security\\cacerts] does not contain any non-DoD-approved certificates. 

If any non-DoD-approved certificate authorities are listed as trusted, this is a finding.

2. Log on to the machine hosting ArcGIS Server. Open Certificate Manager. (You can do this by clicking the "Start" button, typing "certmgr.msc" into the "Search" box, and pressing the "ENTER" key.)

In the "Certificate Manager" window, click "Trusted Root Certificate Authorities", then click" Certificates".

Verify that the Windows Keystore does not contain any non-DoD-approved certificates.

If any non-DoD-approved certificate authorities are listed as trusted, this is a finding.

3. Use a Java-compatible tool to access the Java Keystore at [C:\\arcgisserver\\config-store\\machines\\machine_name\\arcgis.keystore].

The password is the value of the "password" field within the [C:\\arcgisserver\\config-store\\security\\super\\super.json] file.

Verify that the Java Keystore [C:\\arcgisserver\\config-store\\machines\\machine_name\\arcgis.keystore] does not contain any non-DoD-approved certificates. 

If any non-DoD-approved certificate authorities are listed as trusted, this is a finding.'
  desc 'fix', 'Configure the ArcGIS Server to only allow the use of DoD PKI established certificate authorities for verification of the establishment of protected sessions. Substitute the target environment’s values for [bracketed] variables.

Use a Java-compatible tool to access the Java keystore at [C:\\Program Files\\ArcGIS\\Server\\framework\\runtime\\jre\\lib\\security\\cacerts].

The password for the keystore is "changeit".

Remove any non-DoD-approved certificates.

Log on to the machine hosting ArcGIS Server. Open Certificate Manager. (You can do this by clicking the "Start" button, then typing "certmgr.msc" into the "Search" box, and pressing the "ENTER" key.)

In the "Certificate Manager" window, click "Trusted Root Certificate Authorities", then click "Certificates".

Remove any non-DoD-approved certificates.

Use a Java-compatible tool to access the Java Keystore at [C:\\arcgisserver\\config-store\\machines\\machine_name\\arcgis.keystore].

The password is the value of the "password" field within the [C:\\arcgisserver\\config-store\\security\\super\\super.json] file.

Remove any non-DoD-approved certificates.'
  impact 0.7
  ref 'DPMS Target ArcGIS for Server 10-3'
  tag check_id: 'C-40558r642834_chk'
  tag severity: 'high'
  tag gid: 'V-237339'
  tag rid: 'SV-237339r879798_rule'
  tag stig_id: 'AGIS-00-000194'
  tag gtitle: 'SRG-APP-000427'
  tag fix_id: 'F-40521r642835_fix'
  tag 'documentable'
  tag legacy: ['SV-80009', 'V-65519']
  tag cci: ['CCI-002470']
  tag nist: ['SC-23 (5)']
end
