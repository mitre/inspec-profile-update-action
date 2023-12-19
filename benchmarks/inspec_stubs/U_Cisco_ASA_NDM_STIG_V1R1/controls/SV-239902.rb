control 'SV-239902' do
  title 'The Cisco ASA must be configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc 'Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users.'
  desc 'check', 'Review the Cisco ASA configuration to verify that it is compliant with this requirement as shown in the example below.

banner login You are accessing a U.S. Government (USG) Information System (IS) that is provided
banner login for USG-authorized use only.
banner login 
banner login By using this IS (which includes any device attached to this IS), you consent to the
banner login following conditions:
banner login 
banner login -The USG routinely intercepts and monitors communications on this IS for purposes
banner login including, but not limited to, penetration testing, COMSEC monitoring, network
banner login operations and defense, personnel misconduct (PM), law enforcement (LE), and 
banner login counterintelligence (CI) investigations.
banner login 
banner login -At any time, the USG may inspect and seize data stored on this IS.
banner login 
banner login -Communications using, or data stored on, this IS are not private, are subject to routine
banner login monitoring, interception, and search, and may be disclosed or used for any USG-
banner login authorized purpose.
banner login 
banner login -This IS includes security measures (e.g., authentication and access controls) to protect
banner login USG interests--not for your personal benefit or privacy.
banner login 
banner login -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI
banner login investigative searching or monitoring of the content of privileged communications, or 
banner login work product, related to personal representation or services by attorneys, 
banner login psychotherapists, or clergy, and their assistants.  Such communications and work product
banner login are private and banner login confidential.  See User Agreement for details.

If the Cisco ASA is not configured to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device, this is a finding.'
  desc 'fix', 'ASA(config)# banner login You are accessing a U.S. Government (USG) Information System (IS) that is provided
ASA(config)# banner login for USG-authorized use only.
ASA(config)# banner login 
ASA(config)# banner login By using this IS (which includes any device attached to this IS), you consent to the
ASA(config)# banner login following conditions:
ASA(config)# banner login 
ASA(config)# banner login -The USG routinely intercepts and monitors communications on this IS for purposes
ASA(config)# banner login including, but not limited to, penetration testing, COMSEC monitoring, network
ASA(config)# banner login operations and defense, personnel misconduct (PM), law enforcement (LE), and 
ASA(config)# banner login counterintelligence (CI) investigations.
ASA(config)# banner login 
ASA(config)# banner login -At any time, the USG may inspect and seize data stored on this IS.
ASA(config)# banner login 
ASA(config)# banner login -Communications using, or data stored on, this IS are not private, are subject to routine
ASA(config)# banner login monitoring, interception, and search, and may be disclosed or used for any USG-
ASA(config)# banner login authorized purpose.
ASA(config)# banner login 
ASA(config)# banner login -This IS includes security measures (e.g., authentication and access controls) to protect
ASA(config)# banner login USG interests--not for your personal benefit or privacy.
ASA(config)# banner login 
ASA(config)# banner login -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI
ASA(config)# banner login investigative searching or monitoring of the content of privileged communications, or 
ASA(config)# banner login work product, related to personal representation or services by attorneys, 
ASA(config)# banner login psychotherapists, or clergy, and their assistants.  Such communications and work product
ASA(config)# banner login are private and ASA(config)# banner login confidential.  See User Agreement for details.
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43135r666067_chk'
  tag severity: 'medium'
  tag gid: 'V-239902'
  tag rid: 'SV-239902r666069_rule'
  tag stig_id: 'CASA-ND-000160'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag fix_id: 'F-43094r666068_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']
end
