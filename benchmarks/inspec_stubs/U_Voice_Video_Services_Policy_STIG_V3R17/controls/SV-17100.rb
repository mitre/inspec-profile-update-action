control 'SV-17100' do
  title 'The integrity of a PC Communications Application, upgrade, or patch is not validated via digital signature before installation.'
  desc 'It is important that the PC Communications application is not modified during its delivery and installation. This can be a problem if the application is obtained from a source other than directly from it’s original developing vendor such as a third party download service. Any application that is not obtained from its original developing vendor could be modified to add some sort of malicious code that could affect the confidentiality, integrity, and availability of the communications supported by the application. Malicious code could also affect the platform on which the application is operated, the network to which the platform is attached, and the communications system with which the application operates. To mitigate this issue, it is highly recommended that vendors provide their applications in a digitally signed and hashed format such that the integrity of the application can be verified.'
  desc 'check', 'Interview the IAO to validate compliance with the following requirement:

Ensure PC voice, video, UC, or collaboration communications applications, upgrades, and patches are digitally signed by the vendor and validated for integrity before installation.

Determine if PC voice, video, UC, or collaboration communications applications, upgrades, and patches are digitally signed by the vendor and validated for integrity before installation. Have the IAO or SA demonstrate the application and upgrade/patch integrity validation process. This is a finding if digital signatures are not validated before installation.'
  desc 'fix', 'Ensure PC voice, video, UC, or collaboration communications applications, upgrades, and patches are digitally signed by the vendor and validated for integrity before installation.

Employ only those PC voice, video, UC, or collaboration communications applications, upgrades, and patches that are digitally signed by the vendor. Perform the appropriate digital signature validation process to validate application and upgrade/patch integrity before installation.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-17156r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16112'
  tag rid: 'SV-17100r1_rule'
  tag stig_id: 'VVoIP 1710 (GENERAL)'
  tag gtitle: 'Deficient Integrity: PC Comm App Digital Signature'
  tag fix_id: 'F-16218r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'NONE'
  tag potential_impacts: 'Compromise of the supported communications or the supporting network'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
