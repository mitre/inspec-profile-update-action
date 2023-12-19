control 'SV-80483' do
  title 'Trend Deep Security must install security-relevant software updates within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 

Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 

This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.

The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure security-relevant software updates are installed within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).

Review the Scheduled Tasks under Administration >> Scheduled Tasks to see if “Daily Check for Security Updates” is present. 

If “Daily Check for Security Updates” is not present, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to install security-relevant software updates within the time period directed by an authoritative source (e.g., IAVM, CTOs, DTMs, and STIGs).

Go to Scheduled Tasks under the “Administration” tab and click “New”.
Under “Type”, select “Check for Security Updates.” Choose the” Daily” option, and click “Next”. 
Select a start date and time for the daily tasks, then choose “Every Day” and click “Next”.
Select the computers or groups according to the organizations custom policy, and click “Next”.
Enter a unique name for the scheduled task, chose the “Task Enabled” option, and click “Finish”.'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66641r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65993'
  tag rid: 'SV-80483r1_rule'
  tag stig_id: 'TMDS-00-000325'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-72069r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
