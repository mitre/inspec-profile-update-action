control 'SV-254872' do
  title 'The Tanium operating system (TanOS) must install security-relevant firmware updates within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with firmware are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant firmware updates. Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant firmware may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

Patch criticality, as well as system criticality will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant firmware updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant firmware updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', '1. Access the Tanium Server interactively.

2. Check the version number of the installed TanOS release displayed at the bottom of the main menu.

3. Compare to the latest available release on https://kb.tanium.com/Category:TanOS.

4. If the installed release is not the current release, review the release notes for the current release and any other releases newer than the current version to check for security-relevant updates and when they were released.

If there are security-relevant updates that have not been installed within the directed time period, this is a finding.'
  desc 'fix', '1. Download the target TanOS upgrade file from Tanium.

2. Transfer the upgrade to the SFTP incoming folder on the TanOS appliance.

3. Access the Tanium Server interactively.

4. Press "B" for "Appliance Maintenance Menu," and then press "Enter".

5. Press "3" for "Upgrade TanOS," and then press "Enter".

5b. If this TanOS server is part of an appliance array, type "yes" and then press "Enter" to choose to upgrade all appliances in the array.

6. Press "1" (or the appropriate number if there are multiple upgrade files to select from) to choose the upgrade file to install.

7. Review the upgrade version confirmation and type "Yes" and then press "Enter" to begin the upgrade.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58485r866155_chk'
  tag severity: 'medium'
  tag gid: 'V-254872'
  tag rid: 'SV-254872r866157_rule'
  tag stig_id: 'TANS-OS-001520'
  tag gtitle: 'SRG-OS-000440'
  tag fix_id: 'F-58429r866156_fix'
  tag 'documentable'
  tag cci: ['CCI-002607']
  tag nist: ['SI-2 c']
end
