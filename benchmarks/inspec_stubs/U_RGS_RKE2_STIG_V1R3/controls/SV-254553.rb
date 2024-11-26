control 'SV-254553' do
  title 'Rancher RKE2 must protect authenticity of communications sessions with the use of FIPS-validated 140-2 or 140-3 security requirements for cryptographic modules.'
  desc 'Use strong TLS settings.

RKE2 uses FIPS validated BoringCrypto modules. RKE2 Server can prohibit the use of SSL and unauthorized versions of TLS protocols to properly secure communication. There is a lot of traffic between RKE2 nodes to deploy, update, and delete resources so it is important to set strong TLS settings on top of this default feature. It is also important to use approved cypher suites. This ensures the protection of the transmitted information, confidentiality, and integrity so that the attacker cannot read or alter this communication.

The use of unsupported protocol exposes vulnerabilities to the Kubernetes by rogue traffic interceptions, man-in-the-middle attacks, and impersonation of users or services from the container platform runtime, registry, and key store.

To enable the enforcement of minimum version of TLS and cipher suites to be used by the various components of RKE2, the settings "tls-min-version" and "tls-cipher-suites" must be set.

Further documentation of the FIPS modules can be found here: https://docs.rke2.io/security/fips_support.

'
  desc 'check', 'Use strong TLS settings. 

On an RKE2 server, run each command: 

/bin/ps -ef | grep kube-apiserver | grep -v grep

/bin/ps -ef | grep kube-controller-manager | grep -v grep 

/bin/ps -ef | grep kube-scheduler | grep -v grep

For each, look for the existence of tls-min-version (use this command for an aid "| grep tls-min-version"): 
If the setting "tls-min-version" is not configured or it is set to "VersionTLS10" or "VersionTLS11", this is a finding.

For each, look for the existence of the tls-cipher-suites. 
If "tls-cipher-suites" is not set for all servers, or does not contain the following, this is a finding: 

--tls-cipher-suites=TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384,
TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, 
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 
124 | P a g eTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, TLS_RSA_WITH_3DES_EDE_CBC_SHA,
TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_GCM_SHA256, 
TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384'
  desc 'fix', 'Use strong TLS settings.

Edit the RKE2 Server configuration file on all RKE2 Server hosts, located at /etc/rancher/rke2/config.yaml, to contain the following:

kube-controller-manager-arg: 
- "tls-min-version=VersionTLS12" [or higher]
- "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
kube-scheduler-arg: 
- "tls-min-version=VersionTLS12"
- "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
kube-apiserver-arg: 
- "tls-min-version=VersionTLS12"
- "tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"

Once configuration file is updated, restart the RKE2 Server. Run the command:
systemctl restart rke2-server'
  impact 0.7
  ref 'DPMS Target RGS RKE2'
  tag check_id: 'C-58037r894450_chk'
  tag severity: 'high'
  tag gid: 'V-254553'
  tag rid: 'SV-254553r894451_rule'
  tag stig_id: 'CNTR-R2-000010'
  tag gtitle: 'SRG-APP-000014-CTR-000035'
  tag fix_id: 'F-57986r859228_fix'
  tag satisfies: ['SRG-APP-000014-CTR-000035', 'SRG-APP-000014-CTR-000040', 'SRG-APP-000219-CTR-000550', 'SRG-APP-000441-CTR-001090', 'SRG-APP-000442-CTR-001095', 'SRG-APP-000514-CTR-001315', 'SRG-APP-000560-CTR-001340', 'SRG-APP-000605-CTR-001380', 'SRG-APP-000610-CTR-001385', 'SRG-APP-000635-CTR-001405', 'SRG-APP-000645-CTR-001410']
  tag 'documentable'
  tag cci: ['CCI-000068', 'CCI-000185', 'CCI-000382', 'CCI-000803', 'CCI-001184', 'CCI-001453', 'CCI-002420', 'CCI-002422', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'IA-5 (2) (b) (1)', 'CM-7 b', 'IA-7', 'SC-23', 'AC-17 (2)', 'SC-8 (2)', 'SC-8 (2)', 'SC-13 b']
end
