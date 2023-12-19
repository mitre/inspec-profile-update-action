control 'SV-21541' do
  title 'The integrity of a vendor provided application, upgrade, or patch is not validated via digital signature before installation.'
  desc 'It is important that the vendor provided upgrades or patches are not modified during their delivery and installation. This can be a problem if the application is obtained from a source other than directly from it’s original developing vendor such as a third party download service. Any application that is not obtained from its original developing vendor could be modified to add some sort of malicious code that could affect the confidentiality, integrity, and availability of the communications supported by the application. Also malicious code could affect the platform on which the application is operated, the network to which the platform is attached, and the communications system with which the application operates. To mitigate this issue, it is highly recommended that vendors provide their applications, upgrades, or patches in a digitally signed and hashed format such that the integrity of the application can be verified.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure VVoIP system applications, upgrades, and patches are digitally signed by the vendor and validated for integrity before installation.

Determine if VVoIP system applications, upgrades, and patches are digitally signed by the vendor and validated for integrity before installation. Have the IAO or SA demonstrate the application and upgrade/patch integrity validation process. This is a finding if digital signatures are not validated before installation.

NOTE: This requirement addresses applications, upgrades, and patches for the overall VVoIP system infrastructure. PC based applications, upgrades, and patches are addressed separately.'
  desc 'fix', 'Ensure VVoIP system applications, upgrades, and patches are digitally signed by the vendor and validated for integrity before installation.

Employ only those VVoIP system applications, upgrades, and patches that are digitally signed by the vendor. Perform the appropriate digital signature validation process to validate application and upgrade/patch integrity before installation.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23772r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19482'
  tag rid: 'SV-21541r1_rule'
  tag stig_id: 'VVoIP 1201 (GENERAL)'
  tag gtitle: 'Deficient Integrity: Vendor’s App, Upgrade, Patch'
  tag fix_id: 'F-20210r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'None'
  tag potential_impacts: 'Compromise of the supported communications or the supporting infrastructure'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
