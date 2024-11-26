control 'SV-217312' do
  title 'The Juniper router must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement as shown in the example below:

System {
    }
    login {
        message "You are accessing a U.S. Government (USG) Information System (IS) that is provided\\nfor USG-authorized use only.\\n\\nBy using this IS (which includes any device attached to this IS), you consent to the\\nfollowing conditions:\\n\\n-The USG routinely intercepts and monitors communications on this IS for purposes\\nincluding, but not limited to, penetration testing, COMSEC monitoring, network\\noperations and defense, personnel misconduct (PM), law enforcement (LE), and\\ncounterintelligence (CI) investigations.\\n\\n-At any time, the USG may inspect and seize data stored on this IS.\\n\\n-Communications using, or data stored on, this IS are not private, are subject to routine\\nmonitoring, interception, and search, and may be disclosed or used for any USG-\\nauthorized purpose.\\n\\n-This IS includes security measures (e.g., authentication and access controls) to protect\\nUSG interests--not for your personal benefit or privacy.\\n\\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI\\ninvestigative searching or monitoring of the content of privileged communications, or\\nwork product, related to personal representation or services by attorneys,\\npsychotherapists, or clergy, and their assistants.  Such communications and work product\\nare private and confidential.  See User Agreement for details.";
 }

If the router is not configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device, this is a finding.'
  desc 'fix', 'Configure the router to display the Standard Mandatory DoD Notice and Consent Banner before granting access as shown in the following example:

[edit system login]
set message "You are accessing a U.S. Government (USG) Information System (IS) that is provided\\nfor USG-authorized use only.\\n\\nBy using this IS (which includes any device attached to this IS), you consent to the\\nfollowing conditions:\\n\\n-The USG routinely intercepts and monitors communications on this IS for purposes\\nincluding, but not limited to, penetration testing, COMSEC monitoring, network\\noperations and defense, personnel misconduct (PM), law enforcement (LE), and\\ncounterintelligence (CI) investigations.\\n\\n-At any time, the USG may inspect and seize data stored on this IS.\\n\\n-Communications using, or data stored on, this IS are not private, are subject to routine\\nmonitoring, interception, and search, and may be disclosed or used for any USG-\\nauthorized purpose.\\n\\n-This IS includes security measures (e.g., authentication and access controls) to protect\\nUSG interests--not for your personal benefit or privacy.\\n\\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI\\ninvestigative searching or monitoring of the content of privileged communications, or\\nwork product, related to personal representation or services by attorneys,\\npsychotherapists, or clergy, and their assistants.  Such communications and work product\\nare private and confidential.  See User Agreement for details."'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18539r296514_chk'
  tag severity: 'medium'
  tag gid: 'V-217312'
  tag rid: 'SV-217312r879547_rule'
  tag stig_id: 'JUNI-ND-000160'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-18537r296515_fix'
  tag 'documentable'
  tag legacy: ['SV-101207', 'V-91107']
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
