control 'SV-8844' do
  title 'Software patches for critical VoIP servers and other IPT devices DO NOT originate from the system manufacturer and are NOT applied in accordance with manufacturer’s instructions.'
  desc 'VVoIP systems and particularly voice telecommunications systems (that is to say phone systems) are considered critical infrastructure for communications, security, and life safety. As such they are considered mission critical and we have become accustomed to their high reliability and availability which is generally on the order of 5 nines. 

Many VVoIP systems are based on general-purpose operating systems such as Windows, Unix, LINUX as well as database and web server applications such as MS-SQL, Oracle, IIS, Tomcat, and others. Additionally, vendors of these systems usually customize or only use portions of the general-purpose operating systems and applications. Vendors also use and potentially customize open source software (OSS).

Vulnerabilities are discovered every day in these general-purpose operating systems and applications by the community their original vendors.  The vendors of these general-purpose systems and applications (such as Microsoft and others) routinely provide patches for their products to address bugs and vulnerabilities while other vendors and the OSS community provide upgraded versions of the software. These vulnerabilities and their mitigations usually appear in the DOD’s Information Assurance Vulnerability Management (IAVM) process as Information Assurance Vulnerability Alerts (IAVAs). The process mandates that these IAVAs be addressed in a specific time frame based on the severity of the issue. Many times the mandated “fix” is to apply the original vendors patch or to upgrade to the “fixed” version of the software that has the vulnerability.

Due to the mission critical nature of our voice telecommunications systems, owners and operators must be cautioned against applying patches to their systems that are provided by the original vendor of the general-purpose operating systems and applications used in their systems as these may severely and adversely affect the operability of a portion of the system or may cause the system to crash. Significant down time could result which would amount to a self imposed denial of service.

To prevent operability issues and downtime to the greatest extent possible, the VVoIP system vendor must first determine if the OEM vulnerability and mitigating patch is applicable to their system or a portion thereof, and then test the mitigation/patch to validate that it will not degrade the system or its security. The IPT / VoIP vendor may have to modify the OEM patch or produce their own patch before releasing it to their customers. Obtaining a vendor tested and vendor approved patch from the system vendor provides the greatest assurance that responding to an IAVA will not involve a negative impact on the system.

To aid in this process, VVoIP system vendor must be advised of IAVAs that may apply to their systems. This is best accomplished by asking the vendor if the CVE or OEM patch number noted in the IAVA applies to your system and version of code. If so, they probably already have a tested and approved patch available for their customers. If not they will be alerted to the fact they need to provide one or test and approve the application of the OEM mitigation.'
  desc 'check', 'Interview the IAO and review site documentation to confirm compliance with the following requirement: Ensure that software patches for critical, VVoIP servers and other related devices originate from or are approved by the system vendor/manufacturer and are applied in accordance with their instructions. Third party OEM upgrades/patches from general-purpose OS and application vendors or the OSS community are not to be applied without the system vendor’s approval and assurance that such application will not impact the system negatively. 

NOTE: This includes patches or mitigations required by IAVAs. IAVA vulnerabilities must be referred to the system vendor to determine applicability and a mitigation path.'
  desc 'fix', 'Ensure that software patches for critical, VVoIP servers and other related devices originate from or are approved by the system vendor/manufacturer and are applied in accordance with their instructions. Third party OEM upgrades/patches from general-purpose OS and application vendors or the OSS community are not to be applied without the system vendor’s approval and assurance that such application will not impact the system negatively. Note: This includes patches or mitigations required by IAVAs. IAVA vulnerabilities must be referred to the system vendor to determine applicability and a mitigation path.

Only Apply vendor-approved or vendor supplied patches. Correct site policy to require only vendor provided and approved patches are applied.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23623r1_chk'
  tag severity: 'medium'
  tag gid: 'V-8349'
  tag rid: 'SV-8844r1_rule'
  tag stig_id: 'VVoIP 1200 (GENERAL)'
  tag gtitle: 'Deficient COOP: Vendor orig’d Patches vs 3rd Prty'
  tag fix_id: 'F-20138r1_fix'
  tag 'documentable'
  tag potential_impacts: 'Denial of Service. Patches that have not been approved and provided by a vendor and/or applied in conflict with vendor’s instructions can break features or disable the system.'
  tag responsibility: 'Information Assurance Officer'
end
