control 'SV-221607' do
  title 'Splunk Enterprise must use HTTPS/SSL for access to the user interface.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

Anti-replay is a cryptographically based mechanism; thus, it must use FIPS-approved algorithms. An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. Note that the anti-replay service is implicit when data contains monotonically increasing sequence numbers and data integrity is assured. Use of DoD PKI is inherently compliant with this requirement for user and device access. Use of Transport Layer Security (TLS), including application protocols, such as HTTPS and DNSSEC, that use TLS/SSL as the underlying security protocol is also complaint.

Configure the information system to use the hash message authentication code (HMAC) algorithm for authentication services to Kerberos, SSH, web management tool, and any other access method.'
  desc 'check', 'This check is performed on the machine used as a search head, which may be a separate machine in a distributed environment.

If the instance being reviewed is not used as a search head, this check in N/A.

Select Settings >> Server Settings >> General Settings and verify that Enable SSL in Splunk Web is set.

If Enable SSL is not set, this is a finding.'
  desc 'fix', 'This configuration is performed on the machine used as a search head, which may be a separate machine in a distributed environment.

Edit the following file in the installation to configure Splunk to use SSL certificates:

$SPLUNK_HOME/etc/system/local/web.conf

(Note that these files may exist in one of the following folders or its subfolders:
$SPLUNK_HOME/etc/apps/
$SPLUNK_HOME/etc/slave-apps/)

[settings]
enableSplunkWebSSL = true
privKeyPath = <path to the private key generated for the DoD approved certificate>
serverCert = <path to the DoD approved certificate in PEM format>'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 7.x for Windows'
  tag check_id: 'C-23322r416278_chk'
  tag severity: 'medium'
  tag gid: 'V-221607'
  tag rid: 'SV-221607r879597_rule'
  tag stig_id: 'SPLK-CL-000060'
  tag gtitle: 'SRG-APP-000156-AU-002380'
  tag fix_id: 'F-23311r416279_fix'
  tag 'documentable'
  tag legacy: ['SV-111315', 'V-102363']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
