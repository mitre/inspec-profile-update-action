control 'SV-82675' do
  title 'The Mainframe Product must provide the capability for security administrators to change the auditing to be performed on all application components based on all selectable event criteria within time thresholds defined in site security plan.'
  desc 'If authorized individuals do not have the ability to modify auditing parameters in response to a changing threat environment, the organization may not be able to effectively respond, and important forensic information may be lost.

This requirement enables organizations to extend or limit auditing as necessary to meet organizational requirements. Auditing that is limited to conserve information system resources may be extended to address certain threat situations. In addition, auditing may be limited to a specific set of events to facilitate audit reduction, analysis, and reporting. Organizations can establish time thresholds in which audit actions are changed, for example, near real-time, within minutes, or within hours.'
  desc 'check', 'Examine the installation and configuration settings.

If security administrators do not have the capability to change auditing settings, this is a finding.

If an external security manager (ESM) is used, check the ESM rules and configuration.

If there are no rules for these resources or the rules do not allow update and above access to security administrators in accordance with applicable access control policies, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to allow security administrators the capability to change auditing settings.
 
This can be accomplished by using the ESM.

Configure the ESM to restrict update and above access to system and ESM audit settings to security administrators in accordance with applicable access control policies.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68747r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68185'
  tag rid: 'SV-82675r1_rule'
  tag stig_id: 'SRG-APP-000353-MFP-000113'
  tag gtitle: 'SRG-APP-000353-MFP-000113'
  tag fix_id: 'F-74301r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
