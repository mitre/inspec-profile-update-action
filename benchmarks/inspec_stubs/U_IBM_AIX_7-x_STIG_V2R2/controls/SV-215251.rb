control 'SV-215251' do
  title 'AIX must verify the hash of audit tools.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools with the purpose of providing the capability to hide or erase system activity from the audit logs.

To address this risk, audit tools must be cryptographically signed in order to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.'
  desc 'check', %q(Verify that Trusted Execution (TE) is "on" and "CHKEXEC" is "on" by running the following command:  
# trustchk -p                 
TE=ON
CHKEXEC=ON
CHKSHLIB=OFF
CHKSCRIPT=OFF
CHKKERNEXT=OFF
STOP_UNTRUSTD=OFF
STOP_ON_CHKFAIL=OFF
LOCK_KERN_POLICIES=OFF
TSD_FILES_LOCK=OFF
TSD_LOCK=OFF
TEP=OFF
TLP=OFF

If the result show "TE=OFF" or "CHKEXEC=OFF", this is a finding.

Verify that TSD (Trusted Signature Database) contains all the audit tools and their signatures by running the following command:

# awk '/\/usr\/sbin\/audit/ {print; for(i=1; i<=10; i++) {getline; print}}' /etc/security/tsd/tsd.dat |grep -E "\/usr\/sbin\/audit|cert_tag|signature|hash_value"

/usr/sbin/auditselect:
        cert_tag = 00d3cbd2922627b209
        signature = 8f6044a166ad7d1256a2798432dcb06b528eb6c515f4d2d0af90dd17e6ba05665bd8d39ee8f15e8872e90d3b52e0e25c7be9d62c9c5d71cd16b662fb8511f168b6facb4105cc0e9c19c316e37459ad739b75b6037827f3ba60896eeeec62cf47e7514b10d4813c48cacd76b75dc5b0e1a87f7cd10552992021efb5b44eb33a1a
        hash_value = 002e02eda12663a2c9478e1b5154cc97452c07a68a8b9d5a6ca3408b008d95bb
/usr/sbin/auditstream:
        cert_tag = 00d3cbd2922627b209
        signature = 3d5a678962b684208f3996262a997d8838012c1625d83b7df75d9bb3a83065819ae476a21ada2ec7afd683828d9ce5c9d3eb829ed907d11fc2713d895419cbec5855e96b4a3b36a4f5b3c44a801555727b1ca799026262120b18fe2d93f53da8e95f6560c0cf5ea73dccd7daa9ec3df7e24ede0201b9d632becfb58a8f81fee4
        hash_value = 5c434a89bf2fb50a2c21734a5ecd3c4e0a92c34d6685633d59a93caf1684e515
/usr/sbin/auditpr:
        cert_tag = 00d3cbd2922627b209
        signature = 8356f57d227a85037620ec6f357204a9dd3ceeb89fab2ea8b4dea5529a37d290e111a46e9deca8ebd86b37c50b8b2d27599d09a02353081db9f7140780ace0d9986c8f7265d3d91eed7a2502050a6342c79cf1fd6c9b2633e353fdc3603de3b6fc341b2b7a0c6eb286155ae9542bdbbcc29eba84a50f1f8c4f6f5924403f6556
        hash_value = 34bf3b145327d33f810e939d15ae084711dcd0eb7e7f3ebcb135f5ff7b3ba776
/usr/sbin/auditcat:
        cert_tag = 00d3cbd2922627b209
        signature = abf001ee98c5e81ec730552cd26473221ee14694a7fea06d97ae030f1b8603bafdb3f4917cb50c87c90fc8ff03e8762b05c6b21d1907a05288736fa820fd4a05d38f236fec5cfc3813aeb5b0618294effe0356ac26be0e6701398cf181fb38897c5a2496154bba3eab513caaa74a9abb230ad6948190d24907a107d8968a0c27
        hash_value = 78febbeb1e7e4ca1ed4015fb147d27bd451814ed8c81429b42ee9e2f8301bf58
/usr/sbin/auditbin:
        cert_tag = 00d3cbd2922627b209
        signature = 9bb3fde97a70dd3ee93ecf556cf13e3981d1f0794c7a253701e011956574754eb17922525092f38a3b0f9375aef8fadfe3cb6e47f6aa7424e3449910af6cc6e1754f6fe8c2fb20867af7f9a048485ea2dfcd7b8f718d350d21ec2ffe394423f4c513b22ff9a654f1ef55f6e679424ad0e630404fcfd707ed91d542d64564c601
        hash_value = 2deb07bbdf5b744168bb9484b25c0e61813b546f0dd0555d9b9ebcb8cf17272d
/usr/sbin/auditldap:
        cert_tag = 00d3cbd2922627b209
        signature = ab3ea5ba592ef8d1576f632c6154e10a172fbdad1c6379954a48d76bd2c365848a208dfa698e828008fa73b60daf0ad0ab9ad08035f9df2d39ac21a67873cfac3eb07103858903c47e5d1e264ace01de9599ff3c966b12d8cbc6c2b6e3c97f8c56b7a5a4fa33f15bbe472319266854f83fad57917d9dd0c09383fd2b5df41e6d
        hash_value = f929ca078995a6b2a28d1247e9837e03d06fa2c5b12a6c86e679201192694c8c
/usr/sbin/auditconv:
        cert_tag = 00d3cbd2922627b209
        signature = ab7a0e0e5aa62ec741db601cc1609bf7db6006705a3d6b7001b3aa4da5ab6bcfecea569d6891b67088b2033045fdf6532a24433711c74fcffc92744884f0f14211a7625c168f11d4b3de2e7083e57a5063933c0eea5b92c6ab9ea1b131ca8fe85143f616887e4d60cfb534da8b3a920c428279ea8eee04bf57ad70da3c69104c
        hash_value = 0d2a989fa77df6984348f5c66d20af1e71aebd5a0d9f85551873563ee9d851d7
/usr/sbin/audit:
        cert_tag = 00d3cbd2922627b209
        signature = 2b6ed42788eca469aaaf960d4ea9956793182cdbf6b8570ded724762701354f62d003a3ed99db9b4fbb670c5864c9a641d485083789840c71005bbdcc4659dbbfbec0e8c63c8223be9e54f46240e3a5ebed8647fbd9e0e9f2db0d046e0cd73e72c87977c9dc394b61027c2856a27db0e51afb05e07c2d4f8ea3bc33564f2e7a6
        hash_value = 0c5d10f7c7cefec133bee45bd0d30933b18041438a7c7b15b8aa7de60ce208af
/usr/sbin/auditmerge:
        cert_tag = 00d3cbd2922627b209
        signature = 64e0f95c1efa90f34b6ddd370fc0a277db2858b01b993a2f32eb9f0c86e6d901675f67f42158015ceafa37507a0bc36bbd58aca6685464f8b43edb099db670aa497db349c51fc0ed6066da43e2eb5529af8bbdd0c30b66b22158261c224213fc406ffee36e4df476107f867d8f7c09c24e4318a13e2b279d200a9fa4a8b515e4
        hash_value = 6b4a1d1288a1d7e987ad14b395d0067890574a09956171bb32b9a022dc975015

If any of the cert_tag, signature, or hash values is missing or “= VOLATILE", this is a finding.)
  desc 'fix', 'Turn on Trusted Execution and check the integrity of audit tools. 
# /usr/sbin/trustchk -p TE=ON CHKEXEC=ON

If audit tool integrity data is missing from "/etc/security/tsd/tsd.dat", re-install the "bos.rte.security" fileset from AIX DVD using the installp command (assume the DVD is mounted to /dev/cd0):
# installp -aXYqg -d /dev/cd0 bos.rte.security'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16449r294204_chk'
  tag severity: 'medium'
  tag gid: 'V-215251'
  tag rid: 'SV-215251r508663_rule'
  tag stig_id: 'AIX7-00-002028'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag fix_id: 'F-16447r294205_fix'
  tag 'documentable'
  tag legacy: ['V-91489', 'SV-101587']
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end
