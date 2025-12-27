control 'SV-238432' do
  title 'Vendor-supported software must be evaluated and patched against newly found vulnerabilities.'
  desc 'Security faults with software applications and operating systems are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling, must also be  addressed expeditiously. 

Anytime new software code is introduced to a system there is the potential for unintended consequences. There have been documented instances where the application of a patch has caused problems with system integrity or availability.  Due to information system integrity and availability concerns, organizations must give careful consideration to the methodology used to carry out automatic updates.  

Unsupported software versions are not patched by vendors to address newly discovered security versions. An unpatched version is vulnerable to attack.'
  desc 'check', 'Follow the vendor instruction for determining the product version number. View the vendor-provided list of supported versions. To be considered supported, the vendor must report that the version is supported by security patches to reported vulnerabilities. If the security patch support for the installed version cannot be determined or the version is not shown as supported, this is a finding.

If the software does not contain the latest security patches, this is a finding.

Oracle produces security patches on a quarterly basis on or about the fifteenth of the month. The first patch of a calendar year is delivered in January and then April, July and October respectively. There is an automated notice that is available to anyone with access to My Oracle Support. Check to see if the DBA or Administrator of the Oracle account at My Oracle Support is registered to receive the Oracle Security Patch notice. This notice is available to anyone with a valid My Oracle Support. The security notification contains information on the current security update and also the platforms and versions that will be supported by the next patch. For complete information on the availability of the security patch for your specific system, please refer to the Oracle Lifetime Support Policy. Check My Oracle Support for the latest Oracle Quarterly Patch Update patch number, and then check the inventory of the instance you are reviewing and see if the latest security patch is installed using the following command.

Issue the following command:

$ <ORACLE_HOME>/OPatch/opatch lsinventory -detail -oh <ORACLE_HOME>

Check to see if the latest available patch is installed. 

If the latest available patch is not installed, this is a finding.'
  desc 'fix', 'Upgrade the DBMS to a vendor-supported version.

Apply the latest DBMS patches.'
  impact 0.7
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41643r667468_chk'
  tag severity: 'high'
  tag gid: 'V-238432'
  tag rid: 'SV-238432r667470_rule'
  tag stig_id: 'O112-C1-011100'
  tag gtitle: 'SRG-APP-000456-DB-000390'
  tag fix_id: 'F-41602r667469_fix'
  tag 'documentable'
  tag legacy: ['V-52327', 'SV-66543']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
